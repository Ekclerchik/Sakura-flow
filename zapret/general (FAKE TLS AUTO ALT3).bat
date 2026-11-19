@echo off
chcp 65001 > nul

cd /d "%~dp0"
call service.bat status_zapret
call service.bat check_updates
call service.bat load_game_filter
call service.bat load_user_lists
echo:

set "BIN=%~dp0bin\"
set "LISTS=%~dp0lists\"
cd /d %BIN%

start "zapret: %~n0" /min "%BIN%winws.exe" --wf-tcp=80,443,2053,2083,2087,2096,8443,%GameFilterTCP% --wf-udp=443,7000-9000,5000-5500,19294-19344,50000-50100,%GameFilterUDP% ^
--filter-udp=443 --hostlist="%LISTS%list-general.txt" --hostlist-exclude="%LISTS%list-exclude.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" --dpi-desync=fake --dpi-desync-repeats=8 --dpi-desync-fake-quic="%BIN%quic_initial_www_google_com.bin" --new ^
--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-fake-discord="%BIN%quic_initial_www_google_com.bin" --dpi-desync-fake-stun="%BIN%quic_initial_www_google_com.bin" --dpi-desync-repeats=6 --new ^
--filter-tcp=2053,2083,2087,2096,8443 --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern="%BIN%tls_clienthello_4pda_to.bin" --dpi-desync-fake-tls-mod=rnd,dupsid,sni=4pda.to --new ^
--filter-tcp=443 --hostlist="%LISTS%list-google.txt" --ip-id=zero --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-fake-tls-mod=rnd,dupsid,sni=google.com --new ^
--filter-udp=443 --hostlist="%LISTS%list-google.txt" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic="%BIN%quic_initial_www_google_com.bin" --new ^
--filter-tcp=80,443 --hostlist="%LISTS%list-general.txt" --hostlist-exclude="%LISTS%list-exclude.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern="%BIN%tls_clienthello_4pda_to.bin" --dpi-desync-fake-tls-mod=rnd,dupsid,sni=4pda.to --new ^
--filter-udp=443 --ipset="%LISTS%ipset-all.txt" --hostlist-exclude="%LISTS%list-exclude.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic="%BIN%quic_initial_www_google_com.bin" --new ^
--filter-tcp=80,443,8443 --ipset="%LISTS%ipset-all.txt" --hostlist-exclude="%LISTS%list-exclude.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern="%BIN%tls_clienthello_4pda_to.bin" --dpi-desync-fake-tls-mod=rnd,dupsid,sni=4pda.to --new ^
--filter-tcp=%GameFilterTCP% --ipset="%LISTS%ipset-all.txt" --hostlist-exclude="%LISTS%list-exclude.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" --dpi-desync=fake,multisplit --dpi-desync-any-protocol=1 --dpi-desync-cutoff=n4 --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern="%BIN%tls_clienthello_4pda_to.bin" --dpi-desync-fake-tls-mod=rnd,dupsid,sni=4pda.to --new ^
--filter-udp=9000-9100,15000-15110 --dpi-desync=fake,ipfrag2 --dpi-desync-repeats=8 --dpi-desync-any-protocol=1 --dpi-desync-ttl=5 --dpi-desync-cutoff=d4 --dpi-desync-fake-unknown-udp="%BIN%quic_initial_www_google_com.bin" --new ^
--filter-udp=%GameFilterUDP% --ipset="%LISTS%ipset-all.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" --dpi-desync=fake,ipfrag2 --dpi-desync-repeats=6 --dpi-desync-any-protocol=1 --dpi-desync-ttl=5 --dpi-desync-cutoff=d3 --dpi-desync-fake-unknown-udp="%BIN%quic_initial_4pda.to.bin"