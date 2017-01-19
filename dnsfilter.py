# Copyright (c) 2017, Johan Ymerson
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of sidsd nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Dependencies:
# Unbound
# Python 2.7
# dnspython: https://pypi.python.org/pypi/dnspython

import dns.resolver, dns.reversename

###################################################################
# Settings:

# DNS filter servers to use:
dns_servers = [ "208.67.222.222", "208.67.220.220" ]

# Subnets (/24) that contain the IP's returned for blocked domains:
block_subnets = [ "146.112.61", "67.215.65" ]

# Status code to return for blocked domains:
# This will simply result in a "host not found" error:
#block_returncode = RCODE_REFUSED
# This will return NOERROR and the redirect IP from the DNS filter:
block_returncode = RCODE_NOERROR

###################################################################

def init(id, cfg):
    global resolver
    global dns_servers
    resolver = dns.resolver.Resolver()
    resolver.nameservers = dns_servers
    return True

def deinit(id):
    return True

def inform_super(id, qstate, superqstate, qdata):
    return True

def operate(id, event, qstate, qdata):
    global block_return
    
    if event == MODULE_EVENT_NEW:
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True

    if event == MODULE_EVENT_MODDONE:
        qstate.ext_state[id] = MODULE_FINISHED
        return True

    if event == MODULE_EVENT_PASS:
        qstate.ext_state[id] = MODULE_WAIT_MODULE

        # Pick out the domain to look up
        q = qstate.qinfo.qname_str

        # Look up the domain in the DNS filter
        try:
            answer = resolver.query(q, 'A')
        except:
            answer = []
        if len(answer) > 0:
            blocked = False

            a = str(answer[0]).rstrip('.')

            # Quick check of the returned IP matches any of the known block subnets
            s, dummy = a.rsplit('.', 1) 
            if s in block_subnets:
                # If it does, check the reverse name of the address and find the reason for blocking
                try:
                    rev = resolver.query(dns.reversename.from_address(a), 'PTR')
                    reason, dummy = str(rev[0]).split('.', 1)
                    if reason[:4] == 'hit-':
                        blocked = True
                        reason = reason[4:]
                except:
                    pass
            
            if blocked:
                log_warn("dnsfilter: %s blocked (%s)" % (q.rstrip('.'), reason))
                # If we want to return NOERROR for blocked sites, compose a record to answer with
                if block_returncode == RCODE_NOERROR and qstate.qinfo.qtype in [RR_TYPE_A, RR_TYPE_AAAA, RR_TYPE_TXT]:

                    # Compose a record to answer with
                    msg = DNSMessage(q, qstate.qinfo.qtype, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_AA)
                    if qstate.qinfo.qtype == RR_TYPE_A:
                        record = "%s 0 IN A %s" % (q, str(answer[0]))
                    elif qstate.qinfo.qtype == RR_TYPE_AAAA:
                        record = "%s 0 IN AAAA %s" % (q, '::ffff:' + str(answer[0]))
                    elif qstate.qinfo.qtype == RR_TYPE_TXT:
                        record = "%s 0 IN TXT \"%s\"" % (q, "Blocked (%s)" % reason)
                    msg.answer.append(record)
                        
                    # Return the above record
                    if not msg.set_return_msg(qstate):
                        log_err("msg.set_return_msg() failed!")
                        qstate.ext_state[id] = MODULE_ERROR
                        return True
                    qstate.return_msg.rep.security = 2
                    qstate.return_rcode = RCODE_NOERROR
                    qstate.ext_state[id] = MODULE_FINISHED
                else:
                    # Return specified code for blocked domain, unless NOERROR is specified, then return REFUSED.
                    qstate.return_rcode = RCODE_REFUSED if block_returncode == RCODE_NOERROR else block_returncode
                    qstate.ext_state[id] = MODULE_ERROR
                
        return True

    log_err("dnsfilter: Unsupported event")
    qstate.ext_state[id] = MODULE_ERROR
    return True

log_info("dnsfilter: script loaded.")

