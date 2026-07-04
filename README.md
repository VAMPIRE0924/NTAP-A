# NTAP-A

NTAP-A 鏄?NTAP 鐨勫叕缃戞帶鍒剁鍜屼腑缁х銆傚畠璐熻矗鑺傜偣娉ㄥ唽銆乀AP 鐢ㄦ埛閴存潈銆佽繍琛岄厤缃笅鍙戙€乀AP 浜屽眰甯т腑缁с€丏irect 绛栫暐鎺ュ彛锛屼互鍙?Web/API 绠＄悊鍏ュ彛銆?
## 涓変釜浠撳簱

NTAP 鎷嗘垚涓変釜骞插噣鐨勬簮鐮佷粨搴擄紝鏈€缁堝彲閮ㄧ讲鏂囦欢缁熶竴鏀惧湪鍚勮嚜 GitHub Release锛?
- [NTAP-A](https://github.com/VAMPIRE0924/NTAP-A): 鍏綉鏈嶅姟绔紝璐熻矗绠＄悊 API銆丼QLite 鐘舵€佸簱銆佽妭鐐?TAP 閴存潈銆乀apHub 涓户銆?- [NTAP-B](https://github.com/VAMPIRE0924/NTAP-B): 鑺傜偣绔紝閮ㄧ讲鍦ㄥ鎴蜂晶缃戝叧鎴栧唴缃戜富鏈猴紝杩炴帴 A 骞舵帴鍏ユ湰鍦扮綉缁溿€?- [NTAP-C](https://github.com/VAMPIRE0924/NTAP-C): 瀹㈡埛绔紝Windows 绔彁渚涘浘褰㈢晫闈紝Linux 绔彁渚涘懡浠よ鍏ュ彛銆?
## 涓嬭浇鍜岄儴缃?
姝ｅ紡閮ㄧ讲璇蜂笅杞?GitHub Release 閲岀殑鏈€缁堝彂甯冨寘锛屼笉瑕佺洿鎺ユ嬁婧愮爜鐩綍閲岀殑涓存椂鏂囦欢閮ㄧ讲銆?
鏈€鏂扮増鏈細

https://github.com/VAMPIRE0924/NTAP-A/releases/latest

Linux 鏈嶅姟鍣ㄤ紭鍏堜娇鐢細

```text
NTAP-A-<version>-linux-x64.tar.gz
```

鍩烘湰娴佺▼锛?
```sh
tar -xzf NTAP-A-<version>-linux-x64.tar.gz
cd NTAP-A-<version>-linux-x64
cp conf/ntap-a.conf.example conf/ntap-a.conf
```

棣栨杩愯鍓嶈淇敼閰嶇疆閲岀殑 API key銆佺洃鍚湴鍧€銆丼QLite 鏁版嵁搴撹矾寰勭瓑鍙傛暟銆?
甯哥敤鍛戒护锛?
```sh
bin/ntap-a -c conf/ntap-a.conf initdb
bin/ntap-a -c conf/ntap-a.conf serve
bin/ntap-a -c conf/ntap-a.conf api
```

Release 鍖呭唴甯︽湁鏈嶅姟瀹夎鑴氭湰锛屽彲鐢ㄤ簬鍥哄畾鐩綍閮ㄧ讲锛?
```sh
sudo sh install/install-linux-service.sh
sudo sh install/install-linux-service.sh --enable --start
```

## 婧愮爜鑼冨洿

```text
src/a/       NTAP-A 鏈嶅姟绔簮鐮?src/common/  涓夌鍏变韩鍗忚銆佹棩蹇椼€佺綉缁溿€佹椂闂淬€乥uffer 绛夊叕鍏变唬鐮?conf/        鏈€灏忛厤缃ず渚?```

婧愮爜浠撳簱鍙繚瀛樻簮鐮併€侀厤缃牱渚嬨€丷EADME 鍜?LICENSE锛涙渶缁堝彂甯冨寘鍙斁鍦?GitHub Release銆?
## 瀹夊叏娉ㄦ剰

- 瀵瑰叕缃戞毚闇?API 鍓嶅繀椤讳慨鏀归粯璁?API key銆?- SQLite 鏁版嵁搴撳拰鏃ュ織璺緞搴旀斁鍦ㄦ寔涔呭寲鐩綍銆?- API/Web銆乀AP 涓户銆佽妭鐐硅繛鎺ュ簲鎸夐儴缃茬幆澧冩媶鍒嗙洃鍚湴鍧€鍜岄槻鐏绛栫暐銆?
## License

GPL-3.0-only. See `LICENSE`.

