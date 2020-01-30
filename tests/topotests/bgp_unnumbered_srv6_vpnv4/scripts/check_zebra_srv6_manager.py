from lutil import luCommand

jobj = luCommand('r2','vtysh -c "show segment-routing srv6 sid json"', returnJson=True)

ret = len(jobj['localSids']) == 3
luResult('r2', ret, 'numbere of sid is {}valid'.format('' if ret else 'not '))

sid = jobj['localSids'][1]
ret = (sid['name'] == 'End.DT4' or sid['prefix'] == '2001:db8:2:2:fc3::/80')
luResult('r2', ret, 'sidmngr is {}valid ({},{},{},{})'.format('' if ret else 'not ',
    sid['name'], sid['context'], sid['prefix'], sid['owner']))

sid = jobj['localSids'][2]
ret = (sid['name'] == 'End.DT4' or sid['prefix'] == '2001:db8:2:2:fc4::/80')
luResult('r2', ret, 'sidmngr is {}valid ({},{},{},{})'.format('' if ret else 'not ',
    sid['name'], sid['context'], sid['prefix'], sid['owner']))
