a='''103.41.206.251 #micro2
103.41.206.166 #satu
103.41.207.167 #dua
103.41.207.252 #micro3
103.41.206.243 #portal.tellhealth.id
103.41.206.242 #dua.tellhealth.id
'''
import sys

#iptables -D INPUT -p tcp --dport 30010 -s 103.41.206.251,103.41.206.166,103.41.207.167,103.41.207.252,103.41.206.243,103.41.206.242 -j RETURN
ip = []
for i in a.splitlines():
 i = i.split()[0]
 ip.append(i)
deli = ','

result = deli.join(ip)
port = ['30010','30020','30030']
for i in port:
 print('iptables -I INPUT -p tcp --dport '+i+' -s '+result+' -j RETURN')
 print('iptables -I INPUT -p tcp --dport '+i+' -j DROP')
for i in port:
 print('iptables -D INPUT -p tcp --dport '+i+' -s '+result+' -j RETURN')
 print('iptables -D INPUT -p tcp --dport '+i+' -j DROP')

'''print('iptables -A INPUT -p tcp --dport 30010 -s '+result+' -j ACCEPT')
print('iptables -A INPUT -p tcp --dport 30020 -s '+result+' -j ACCEPT')
print('iptables -A INPUT -p tcp --dport 30030 -s '+result+' -j ACCEPT')
print('iptables -A INPUT -p tcp --dport 30010 -j DROP')
print('iptables -A INPUT -p tcp --dport 30020 -j DROP')
print('iptables -A INPUT -p tcp --dport 30030 -j DROP')
print('iptables -D INPUT -p tcp --dport 30010 -s '+result+' -j ACCEPT')
print('iptables -D INPUT -p tcp --dport 30020 -s '+result+' -j ACCEPT')
print('iptables -D INPUT -p tcp --dport 30030 -s '+result+' -j ACCEPT')
print('iptables -D INPUT -p tcp --dport 30010 -j DROP')
print('iptables -D INPUT -p tcp --dport 30020 -j DROP')
print('iptables -D INPUT -p tcp --dport 30030 -j DROP')
'''
'''try:
except:
 print('Usage: python3 '+sys.argv[0]+' rm/add/list')
'''
