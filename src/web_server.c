/*
 * junkNAS - Minimal web server for browsing and chunk sync
 */

#include "web_server.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <cjson/cJSON.h>

#include "wireguard.h"

#define WEB_BACKLOG 16
#define WEB_BUF_SIZE 8192

struct junknas_web_server {
    junknas_config_t *config;
    int fd;
    pthread_t thread;
    int stop;
};

typedef struct {
    int fd;
    junknas_config_t *config;
} web_conn_t;

static const char qr_lib_js[] __attribute__((unused)) =
    "var qrcode=function(){var t=function(t,r){var e=t,n=g[r],o=null,i=0,a=null,u=[],f={},c=function(t,r){o=function(t){for(var r=new Array(t),e=0;e<t;e+=1){r[e]=new Array(t);for(var n=0;n<t;n+=1)r[e][n]=null}return r}(i=4*e+17),l(0,0),l(i-7,0),l(0,i-7),s(),h(),d(t,r),e>=7&&v(t),null==a&&(a=p(e,n,u)),w(a,r)},l=function(t,r){for(var e=-1;e<=7;e+=1)if(!(t+e<=-1||i<=t+e))for(var n=-1;n<=7;n+=1)r+n<=-1||i<=r+n||(o[t+e][r+n]=0<=e&&e<=6&&(0==n||6==n)||0<=n&&n<=6&&(0==e||6==e)||2<=e&&e<=4&&2<=n&&n<=4)},h=function(){for(var t=8;t<i-8;t+=1)null==o[t][6]&&(o[t][6]=t%2==0);for(var r=8;r<i-8;r+=1)null==o[6][r]&&(o[6][r]=r%2==0)},s=function(){for(var t=B.getPatternPosition(e),r=0;r<t.length;r+=1)for(var n=0;n<t.length;n+=1){var i=t[r],a=t[n];if(null==o[i][a])for(var u=-2;u<=2;u+=1)for(var f=-2;f<=2;f+=1)o[i+u][a+f]=-2==u||2==u||-2==f||2==f||0==u&&0==f}},v=function(t){for(var r=B.getBCHTypeNumber(e),n=0;n<18;n+=1){var a=!t&&1==(r>>n&1);o[Math.floor(n/3)][n%3+i-8-3]=a}for(n=0;n<18;n+=1){a=!t&&1==(r>>n&1);o[n%3+i-8-3][Math.floor(n/3)]=a}},d=function(t,r){for(var e=n<<3|r,a=B.getBCHTypeInfo(e),u=0;u<15;u+=1){var f=!t&&1==(a>>u&1);u<6?o[u][8]=f:u<8?o[u+1][8]=f:o[i-15+u][8]=f}for(u=0;u<15;u+=1){f=!t&&1==(a>>u&1);u<8?o[8][i-u-1]=f:u<9?o[8][15-u-1+1]=f:o[8][15-u-1]=f}o[i-8][8]=!t},w=function(t,r){for(var e=-1,n=i-1,a=7,u=0,f=B.getMaskFunction(r),c=i-1;c>0;c-=2)for(6==c&&(c-=1);;){for(var g=0;g<2;g+=1)if(null==o[n][c-g]){var l=!1;u<t.length&&(l=1==(t[u]>>>a&1)),f(n,c-g)&&(l=!l),o[n][c-g]=l,-1==(a-=1)&&(u+=1,a=7)}if((n+=e)<0||i<=n){n-=e,e=-e;break}}},p=function(t,r,e){for(var n=A.getRSBlocks(t,r),o=b(),i=0;i<e.length;i+=1){var a=e[i];o.put(a.getMode(),4),o.put(a.getLength(),B.getLengthInBits(a.getMode(),t)),a.write(o)}var u=0;for(i=0;i<n.length;i+=1)u+=n[i].dataCount;if(o.getLengthInBits()>8*u)throw\"code length overflow. (\"+o.getLengthInBits()+\">\"+8*u+\")\";for(o.getLengthInBits()+4<=8*u&&o.put(0,4);o.getLengthInBits()%8!=0;)o.putBit(!1);for(;!(o.getLengthInBits()>=8*u||(o.put(236,8),o.getLengthInBits()>=8*u));)o.put(17,8);return function(t,r){for(var e=0,n=0,o=0,i=new Array(r.length),a=new Array(r.length),u=0;u<r.length;u+=1){var f=r[u].dataCount,c=r[u].totalCount-f;n=Math.max(n,f),o=Math.max(o,c),i[u]=new Array(f);for(var g=0;g<i[u].length;g+=1)i[u][g]=255&t.getBuffer()[g+e];e+=f;var l=B.getErrorCorrectPolynomial(c),h=k(i[u],l.getLength()-1).mod(l);for(a[u]=new Array(l.getLength()-1),g=0;g<a[u].length;g+=1){var s=g+h.getLength()-a[u].length;a[u][g]=s>=0?h.getAt(s):0}}var v=0;for(g=0;g<r.length;g+=1)v+=r[g].totalCount;var d=new Array(v),w=0;for(g=0;g<n;g+=1)for(u=0;u<r.length;u+=1)g<i[u].length&&(d[w]=i[u][g],w+=1);for(g=0;g<o;g+=1)for(u=0;u<r.length;u+=1)g<a[u].length&&(d[w]=a[u][g],w+=1);return d}(o,n)};f.addData=function(t,r){var e=null;switch(r=r||\"Byte\"){case\"Numeric\":e=M(t);break;case\"Alphanumeric\":e=x(t);break;case\"Byte\":e=m(t);break;case\"Kanji\":e=L(t);break;default:throw\"mode:\"+r}u.push(e),a=null},f.isDark=function(t,r){if(t<0||i<=t||r<0||i<=r)throw t+\",\"+r;return o[t][r]},f.getModuleCount=function(){return i},f.make=function(){if(e<1){for(var t=1;t<40;t++){for(var r=A.getRSBlocks(t,n),o=b(),i=0;i<u.length;i++){var a=u[i];o.put(a.getMode(),4),o.put(a.getLength(),B.getLengthInBits(a.getMode(),t)),a.write(o)}var g=0;for(i=0;i<r.length;i++)g+=r[i].dataCount;if(o.getLengthInBits()<=8*g)break}e=t}c(!1,function(){for(var t=0,r=0,e=0;e<8;e+=1){c(!0,e);var n=B.getLostPoint(f);(0==e||t>n)&&(t=n,r=e)}return r}())},f.createTableTag=function(t,r){t=t||2;var e=\"\";e+='<table style=\"',e+=\" border-width: 0px; border-style: none;\",e+=\" border-collapse: collapse;\",e+=\" padding: 0px; margin: \"+(r=void 0===r?4*t:r)+\"px;\",e+='\">',e+=\"<tbody>\";for(var n=0;n<f.getModuleCount();n+=1){e+=\"<tr>\";for(var o=0;o<f.getModuleCount();o+=1)e+='<td style=\"',e+=\" border-width: 0px; border-style: none;\",e+=\" border-collapse: collapse;\",e+=\" padding: 0px; margin: 0px;\",e+=\" width: \"+t+\"px;\",e+=\" height: \"+t+\"px;\",e+=\" background-color: \",e+=f.isDark(n,o)?\"#000000\":\"#ffffff\",e+=\";\",e+='\"/>';e+=\"</tr>\"}return e+=\"</tbody>\",e+=\"</table>\"},f.createSvgTag=function(t,r,e,n){var o={};\"object\"==typeof arguments[0]&&(t=(o=arguments[0]).cellSize,r=o.margin,e=o.alt,n=o.title),t=t||2,r=void 0===r?4*t:r,(e=\"string\"==typeof e?{text:e}:e||{}).text=e.text||null,e.id=e.text?e.id||\"qrcode-description\":null,(n=\"string\"==typeof n?{text:n}:n||{}).text=n.text||null,n.id=n.text?n.id||\"qrcode-title\":null;var i,a,u,c,g=f.getModuleCount()*t+2*r,l=\"\";for(c=\"l\"+t+\",0 0,\"+t+\" -\"+t+\",0 0,-\"+t+\"z \",l+='<svg version=\"1.1\" xmlns=\"http://www.w3.org/2000/svg\"',l+=o.scalable?\"\":' width=\"'+g+'px\" height=\"'+g+'px\"',l+=' viewBox=\"0 0 '+g+\" \"+g+'\" ',l+=' preserveAspectRatio=\"xMinYMin meet\"',l+=n.text||e.text?' role=\"img\" aria-labelledby=\"'+y([n.id,e.id].join(\" \").trim())+'\"':\"\",l+=\">\",l+=n.text?'<title id=\"'+y(n.id)+'\">'+y(n.text)+\"</title>\":\"\",l+=e.text?'<description id=\"'+y(e.id)+'\">'+y(e.text)+\"</description>\":\"\",l+='<rect width=\"100%\" height=\"100%\" fill=\"white\" cx=\"0\" cy=\"0\"/>',l+='<path d=\"',a=0;a<f.getModuleCount();a+=1)for(u=a*t+r,i=0;i<f.getModuleCount();i+=1)f.isDark(a,i)&&(l+=\"M\"+(i*t+r)+\",\"+u+c);return l+='\" stroke=\"transparent\" fill=\"black\"/>',l+=\"</svg>\"},f.createDataURL=function(t,r){t=t||2,r=void 0===r?4*t:r;var e=f.getModuleCount()*t+2*r,n=r,o=e-r;return I(e,e,(function(r,e){if(n<=r&&r<o&&n<=e&&e<o){var i=Math.floor((r-n)/t),a=Math.floor((e-n)/t);return f.isDark(a,i)?0:1}return 1}))},f.createImgTag=function(t,r,e){t=t||2,r=void 0===r?4*t:r;var n=f.getModuleCount()*t+2*r,o=\"\";return o+=\"<img\",o+=' src=\"',o+=f.createDataURL(t,r),o+='\"',o+=' width=\"',o+=n,o+='\"',o+=' height=\"',o+=n,o+='\"',e&&(o+=' alt=\"',o+=y(e),o+='\"'),o+=\"/>\"};var y=function(t){for(var r=\"\",e=0;e<t.length;e+=1){var n=t.charAt(e);switch(n){case\"<\":r+=\"&lt;\";break;case\">\":r+=\"&gt;\";break;case\"&\":r+=\"&amp;\";break;case'\"':r+=\"&quot;\";break;default:r+=n}}return r};return f.createASCII=function(t,r){if((t=t||1)<2)return function(t){t=void 0===t?2:t;var r,e,n,o,i,a=1*f.getModuleCount()+2*t,u=t,c=a-t,g={\"██\":\"█\",\"█ \":\"▀\",\" █\":\"▄\",\"  \":\" \"},l={\"██\":\"▀\",\"█ \":\"▀\",\" █\":\" \",\"  \":\" \"},h=\"\";for(r=0;r<a;r+=2){for(n=Math.floor((r-u)/1),o=Math.floor((r+1-u)/1),e=0;e<a;e+=1)i=\"█\",u<=e&&e<c&&u<=r&&r<c&&f.isDark(n,Math.floor((e-u)/1))&&(i=\" \"),u<=e&&e<c&&u<=r+1&&r+1<c&&f.isDark(o,Math.floor((e-u)/1))?i+=\" \":i+=\"█\",h+=t<1&&r+1>=c?l[i]:g[i];h+=\"\\n\"}return a%2&&t>0?h.substring(0,h.length-a-1)+Array(a+1).join(\"▀\"):h.substring(0,h.length-1)}(r);t-=1,r=void 0===r?2*t:r;var e,n,o,i,a=f.getModuleCount()*t+2*r,u=r,c=a-r,g=Array(t+1).join(\"██\"),l=Array(t+1).join(\"  \"),h=\"\",s=\"\";for(e=0;e<a;e+=1){for(o=Math.floor((e-u)/t),s=\"\",n=0;n<a;n+=1)i=1,u<=n&&n<c&&u<=e&&e<c&&f.isDark(o,Math.floor((n-u)/t))&&(i=0),s+=i?g:l;for(o=0;o<t;o+=1)h+=s+\"\\n\"}return h.substring(0,h.length-1)},f.renderTo2dContext=function(t,r){r=r||2;for(var e=f.getModuleCount(),n=0;n<e;n++)for(var o=0;o<e;o++)t.fillStyle=f.isDark(n,o)?\"black\":\"white\",t.fillRect(n*r,o*r,r,r)},f};t.stringToBytes=(t.stringToBytesFuncs={default:function(t){for(var r=[],e=0;e<t.length;e+=1){var n=t.charCodeAt(e);r.push(255&n)}return r}}).default,t.createStringToBytes=function(t,r){var e=function(){for(var e=S(t),n=function(){var t=e.read();if(-1==t)throw\"eof\";return t},o=0,i={};;){var a=e.read();if(-1==a)break;var u=n(),f=n()<<8|n();i[String.fromCharCode(a<<8|u)]=f,o+=1}if(o!=r)throw o+\" != \"+r;return i}(),n=\"?\".charCodeAt(0);return function(t){for(var r=[],o=0;o<t.length;o+=1){var i=t.charCodeAt(o);if(i<128)r.push(i);else{var a=e[t.charAt(o)];\"number\"==typeof a?(255&a)==a?r.push(a):(r.push(a>>>8),r.push(255&a)):r.push(n)}}return r}};var r,e,n,o,i,a=1,u=2,f=4,c=8,g={L:1,M:0,Q:3,H:2},l=0,h=1,s=2,v=3,d=4,w=5,p=6,y=7,B=(r=[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],[6,28,50,72,94],[6,26,50,74,98],[6,30,54,78,102],[6,28,54,80,106],[6,32,58,84,110],[6,30,58,86,114],[6,34,62,90,118],[6,26,50,74,98,122],[6,30,54,78,102,126],[6,26,52,78,104,130],[6,30,56,82,108,134],[6,34,60,86,112,138],[6,30,58,86,114,142],[6,34,62,90,118,146],[6,30,54,78,102,126,150],[6,24,50,76,102,128,154],[6,28,54,80,106,132,158],[6,32,58,84,110,136,162],[6,26,54,82,110,138,166],[6,30,58,86,114,142,170]],e=1335,n=7973,i=function(t){for(var r=0;0!=t;)r+=1,t>>>=1;return r},(o={}).getBCHTypeInfo=function(t){for(var r=t<<10;i(r)-i(e)>=0;)r^=e<<i(r)-i(e);return 21522^(t<<10|r)},o.getBCHTypeNumber=function(t){for(var r=t<<12;i(r)-i(n)>=0;)r^=n<<i(r)-i(n);return t<<12|r},o.getPatternPosition=function(t){return r[t-1]},o.getMaskFunction=function(t){switch(t){case l:return function(t,r){return(t+r)%2==0};case h:return function(t,r){return t%2==0};case s:return function(t,r){return r%3==0};case v:return function(t,r){return(t+r)%3==0};case d:return function(t,r){return(Math.floor(t/2)+Math.floor(r/3))%2==0};case w:return function(t,r){return t*r%2+t*r%3==0};case p:return function(t,r){return(t*r%2+t*r%3)%2==0};case y:return function(t,r){return(t*r%3+(t+r)%2)%2==0};default:throw\"bad maskPattern:\"+t}},o.getErrorCorrectPolynomial=function(t){for(var r=k([1],0),e=0;e<t;e+=1)r=r.multiply(k([1,C.gexp(e)],0));return r},o.getLengthInBits=function(t,r){if(1<=r&&r<10)switch(t){case a:return 10;case u:return 9;case f:case c:return 8;default:throw\"mode:\"+t}else if(r<27)switch(t){case a:return 12;case u:return 11;case f:return 16;case c:return 10;default:throw\"mode:\"+t}else{if(!(r<41))throw\"type:\"+r;switch(t){case a:return 14;case u:return 13;case f:return 16;case c:return 12;default:throw\"mode:\"+t}}},o.getLostPoint=function(t){for(var r=t.getModuleCount(),e=0,n=0;n<r;n+=1)for(var o=0;o<r;o+=1){for(var i=0,a=t.isDark(n,o),u=-1;u<=1;u+=1)if(!(n+u<0||r<=n+u))for(var f=-1;f<=1;f+=1)o+f<0||r<=o+f||0==u&&0==f||a==t.isDark(n+u,o+f)&&(i+=1);i>5&&(e+=3+i-5)}for(n=0;n<r-1;n+=1)for(o=0;o<r-1;o+=1){var c=0;t.isDark(n,o)&&(c+=1),t.isDark(n+1,o)&&(c+=1),t.isDark(n,o+1)&&(c+=1),t.isDark(n+1,o+1)&&(c+=1),0!=c&&4!=c||(e+=3)}for(n=0;n<r;n+=1)for(o=0;o<r-6;o+=1)t.isDark(n,o)&&!t.isDark(n,o+1)&&t.isDark(n,o+2)&&t.isDark(n,o+3)&&t.isDark(n,o+4)&&!t.isDark(n,o+5)&&t.isDark(n,o+6)&&(e+=40);for(o=0;o<r;o+=1)for(n=0;n<r-6;n+=1)t.isDark(n,o)&&!t.isDark(n+1,o)&&t.isDark(n+2,o)&&t.isDark(n+3,o)&&t.isDark(n+4,o)&&!t.isDark(n+5,o)&&t.isDark(n+6,o)&&(e+=40);var g=0;for(o=0;o<r;o+=1)for(n=0;n<r;n+=1)t.isDark(n,o)&&(g+=1);return e+=Math.abs(100*g/r/r-50)/5*10},o),C=function(){for(var t=new Array(256),r=new Array(256),e=0;e<8;e+=1)t[e]=1<<e;for(e=8;e<256;e+=1)t[e]=t[e-4]^t[e-5]^t[e-6]^t[e-8];for(e=0;e<255;e+=1)r[t[e]]=e;var n={glog:function(t){if(t<1)throw\"glog(\"+t+\")\";return r[t]},gexp:function(r){for(;r<0;)r+=255;for(;r>=256;)r-=255;return t[r]}};return n}();function k(t,r){if(void 0===t.length)throw t.length+\"/\"+r;var e=function(){for(var e=0;e<t.length&&0==t[e];)e+=1;for(var n=new Array(t.length-e+r),o=0;o<t.length-e;o+=1)n[o]=t[o+e];return n}(),n={getAt:function(t){return e[t]},getLength:function(){return e.length},multiply:function(t){for(var r=new Array(n.getLength()+t.getLength()-1),e=0;e<n.getLength();e+=1)for(var o=0;o<t.getLength();o+=1)r[e+o]^=C.gexp(C.glog(n.getAt(e))+C.glog(t.getAt(o)));return k(r,0)},mod:function(t){if(n.getLength()-t.getLength()<0)return n;for(var r=C.glog(n.getAt(0))-C.glog(t.getAt(0)),e=new Array(n.getLength()),o=0;o<n.getLength();o+=1)e[o]=n.getAt(o);for(o=0;o<t.getLength();o+=1)e[o]^=C.gexp(C.glog(t.getAt(o))+r);return k(e,0).mod(t)}};return n}var A=function(){var t=[[1,26,19],[1,26,16],[1,26,13],[1,26,9],[1,44,34],[1,44,28],[1,44,22],[1,44,16],[1,70,55],[1,70,44],[2,35,17],[2,35,13],[1,100,80],[2,50,32],[2,50,24],[4,25,9],[1,134,108],[2,67,43],[2,33,15,2,34,16],[2,33,11,2,34,12],[2,86,68],[4,43,27],[4,43,19],[4,43,15],[2,98,78],[4,49,31],[2,32,14,4,33,15],[4,39,13,1,40,14],[2,121,97],[2,60,38,2,61,39],[4,40,18,2,41,19],[4,40,14,2,41,15],[2,146,116],[3,58,36,2,59,37],[4,36,16,4,37,17],[4,36,12,4,37,13],[2,86,68,2,87,69],[4,69,43,1,70,44],[6,43,19,2,44,20],[6,43,15,2,44,16],[4,101,81],[1,80,50,4,81,51],[4,50,22,4,51,23],[3,36,12,8,37,13],[2,116,92,2,117,93],[6,58,36,2,59,37],[4,46,20,6,47,21],[7,42,14,4,43,15],[4,133,107],[8,59,37,1,60,38],[8,44,20,4,45,21],[12,33,11,4,34,12],[3,145,115,1,146,116],[4,64,40,5,65,41],[11,36,16,5,37,17],[11,36,12,5,37,13],[5,109,87,1,110,88],[5,65,41,5,66,42],[5,54,24,7,55,25],[11,36,12,7,37,13],[5,122,98,1,123,99],[7,73,45,3,74,46],[15,43,19,2,44,20],[3,45,15,13,46,16],[1,135,107,5,136,108],[10,74,46,1,75,47],[1,50,22,15,51,23],[2,42,14,17,43,15],[5,150,120,1,151,121],[9,69,43,4,70,44],[17,50,22,1,51,23],[2,42,14,19,43,15],[3,141,113,4,142,114],[3,70,44,11,71,45],[17,47,21,4,48,22],[9,39,13,16,40,14],[3,135,107,5,136,108],[3,67,41,13,68,42],[15,54,24,5,55,25],[15,43,15,10,44,16],[4,144,116,4,145,117],[17,68,42],[17,50,22,6,51,23],[19,46,16,6,47,17],[2,139,111,7,140,112],[17,74,46],[7,54,24,16,55,25],[34,37,13],[4,151,121,5,152,122],[4,75,47,14,76,48],[11,54,24,14,55,25],[16,45,15,14,46,16],[6,147,117,4,148,118],[6,73,45,14,74,46],[11,54,24,16,55,25],[30,46,16,2,47,17],[8,132,106,4,133,107],[8,75,47,13,76,48],[7,54,24,22,55,25],[22,45,15,13,46,16],[10,142,114,2,143,115],[19,74,46,4,75,47],[28,50,22,6,51,23],[33,46,16,4,47,17],[8,152,122,4,153,123],[22,73,45,3,74,46],[8,53,23,26,54,24],[12,45,15,28,46,16],[3,147,117,10,148,118],[3,73,45,23,74,46],[4,54,24,31,55,25],[11,45,15,31,46,16],[7,146,116,7,147,117],[21,73,45,7,74,46],[1,53,23,37,54,24],[19,45,15,26,46,16],[5,145,115,10,146,116],[19,75,47,10,76,48],[15,54,24,25,55,25],[23,45,15,25,46,16],[13,145,115,3,146,116],[2,74,46,29,75,47],[42,54,24,1,55,25],[23,45,15,28,46,16],[17,145,115],[10,74,46,23,75,47],[10,54,24,35,55,25],[19,45,15,35,46,16],[17,145,115,1,146,116],[14,74,46,21,75,47],[29,54,24,19,55,25],[11,45,15,46,46,16],[13,145,115,6,146,116],[14,74,46,23,75,47],[44,54,24,7,55,25],[59,46,16,1,47,17],[12,151,121,7,152,122],[12,75,47,26,76,48],[39,54,24,14,55,25],[22,45,15,41,46,16],[6,151,121,14,152,122],[6,75,47,34,76,48],[46,54,24,10,55,25],[2,45,15,64,46,16],[17,152,122,4,153,123],[29,74,46,14,75,47],[49,54,24,10,55,25],[24,45,15,46,46,16],[4,152,122,18,153,123],[13,74,46,32,75,47],[48,54,24,14,55,25],[42,45,15,32,46,16],[20,147,117,4,148,118],[40,75,47,7,76,48],[43,54,24,22,55,25],[10,45,15,67,46,16],[19,148,118,6,149,119],[18,75,47,31,76,48],[34,54,24,34,55,25],[20,45,15,61,46,16]],r=function(t,r){var e={};return e.totalCount=t,e.dataCount=r,e},e={};return e.getRSBlocks=function(e,n){var o=function(r,e){switch(e){case g.L:return t[4*(r-1)+0];case g.M:return t[4*(r-1)+1];case g.Q:return t[4*(r-1)+2];case g.H:return t[4*(r-1)+3];default:return}}(e,n);if(void 0===o)throw\"bad rs block @ typeNumber:\"+e+\"/errorCorrectionLevel:\"+n;for(var i=o.length/3,a=[],u=0;u<i;u+=1)for(var f=o[3*u+0],c=o[3*u+1],l=o[3*u+2],h=0;h<f;h+=1)a.push(r(c,l));return a},e}(),b=function(){var t=[],r=0,e={getBuffer:function(){return t},getAt:function(r){var e=Math.floor(r/8);return 1==(t[e]>>>7-r%8&1)},put:function(t,r){for(var n=0;n<r;n+=1)e.putBit(1==(t>>>r-n-1&1))},getLengthInBits:function(){return r},putBit:function(e){var n=Math.floor(r/8);t.length<=n&&t.push(0),e&&(t[n]|=128>>>r%8),r+=1}};return e},M=function(t){var r=a,e=t,n={getMode:function(){return r},getLength:function(t){return e.length},write:function(t){for(var r=e,n=0;n+2<r.length;)t.put(o(r.substring(n,n+3)),10),n+=3;n<r.length&&(r.length-n==1?t.put(o(r.substring(n,n+1)),4):r.length-n==2&&t.put(o(r.substring(n,n+2)),7))}},o=function(t){for(var r=0,e=0;e<t.length;e+=1)r=10*r+i(t.charAt(e));return r},i=function(t){if(\"0\"<=t&&t<=\"9\")return t.charCodeAt(0)-\"0\".charCodeAt(0);throw\"illegal char :\"+t};return n},x=function(t){var r=u,e=t,n={getMode:function(){return r},getLength:function(t){return e.length},write:function(t){for(var r=e,n=0;n+1<r.length;)t.put(45*o(r.charAt(n))+o(r.charAt(n+1)),11),n+=2;n<r.length&&t.put(o(r.charAt(n)),6)}},o=function(t){if(\"0\"<=t&&t<=\"9\")return t.charCodeAt(0)-\"0\".charCodeAt(0);if(\"A\"<=t&&t<=\"Z\")return t.charCodeAt(0)-\"A\".charCodeAt(0)+10;switch(t){case\" \":return 36;case\"$\":return 37;case\"%\":return 38;case\"*\":return 39;case\"+\":return 40;case\"-\":return 41;case\".\":return 42;case\"/\":return 43;case\":\":return 44;default:throw\"illegal char :\"+t}};return n},m=function(r){var e=f,n=t.stringToBytes(r),o={getMode:function(){return e},getLength:function(t){return n.length},write:function(t){for(var r=0;r<n.length;r+=1)t.put(n[r],8)}};return o},L=function(r){var e=c,n=t.stringToBytesFuncs.SJIS;if(!n)throw\"sjis not supported.\";!function(){var t=n(\"友\");if(2!=t.length||38726!=(t[0]<<8|t[1]))throw\"sjis not supported.\"}();var o=n(r),i={getMode:function(){return e},getLength:function(t){return~~(o.length/2)},write:function(t){for(var r=o,e=0;e+1<r.length;){var n=(255&r[e])<<8|255&r[e+1];if(33088<=n&&n<=40956)n-=33088;else{if(!(57408<=n&&n<=60351))throw\"illegal char at \"+(e+1)+\"/\"+n;n-=49472}n=192*(n>>>8&255)+(255&n),t.put(n,13),e+=2}if(e<r.length)throw\"illegal char at \"+(e+1)}};return i},D=function(){var t=[],r={writeByte:function(r){t.push(255&r)},writeShort:function(t){r.writeByte(t),r.writeByte(t>>>8)},writeBytes:function(t,e,n){e=e||0,n=n||t.length;for(var o=0;o<n;o+=1)r.writeByte(t[o+e])},writeString:function(t){for(var e=0;e<t.length;e+=1)r.writeByte(t.charCodeAt(e))},toByteArray:function(){return t},toString:function(){var r=\"\";r+=\"[\";for(var e=0;e<t.length;e+=1)e>0&&(r+=\",\"),r+=t[e];return r+=\"]\"}};return r},S=function(t){var r=t,e=0,n=0,o=0,i={read:function(){for(;o<8;){if(e>=r.length){if(0==o)return-1;throw\"unexpected end of file./\"+o}var t=r.charAt(e);if(e+=1,\"=\"==t)return o=0,-1;t.match(/^\\s$/)||(n=n<<6|a(t.charCodeAt(0)),o+=6)}var i=n>>>o-8&255;return o-=8,i}},a=function(t){if(65<=t&&t<=90)return t-65;if(97<=t&&t<=122)return t-97+26;if(48<=t&&t<=57)return t-48+52;if(43==t)return 62;if(47==t)return 63;throw\"c:\"+t};return i},I=function(t,r,e){for(var n=function(t,r){var e=t,n=r,o=new Array(t*r),i={setPixel:function(t,r,n){o[r*e+t]=n},write:function(t){t.writeString(\"GIF87a\"),t.writeShort(e),t.writeShort(n),t.writeByte(128),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(255),t.writeByte(255),t.writeByte(255),t.writeString(\",\"),t.writeShort(0),t.writeShort(0),t.writeShort(e),t.writeShort(n),t.writeByte(0);var r=a(2);t.writeByte(2);for(var o=0;r.length-o>255;)t.writeByte(255),t.writeBytes(r,o,255),o+=255;t.writeByte(r.length-o),t.writeBytes(r,o,r.length-o),t.writeByte(0),t.writeString(\";\")}},a=function(t){for(var r=1<<t,e=1+(1<<t),n=t+1,i=u(),a=0;a<r;a+=1)i.add(String.fromCharCode(a));i.add(String.fromCharCode(r)),i.add(String.fromCharCode(e));var f,c,g,l=D(),h=(f=l,c=0,g=0,{write:function(t,r){if(t>>>r!=0)throw\"length over\";for(;c+r>=8;)f.writeByte(255&(t<<c|g)),r-=8-c,t>>>=8-c,g=0,c=0;g|=t<<c,c+=r},flush:function(){c>0&&f.writeByte(g)}});h.write(r,n);var s=0,v=String.fromCharCode(o[s]);for(s+=1;s<o.length;){var d=String.fromCharCode(o[s]);s+=1,i.contains(v+d)?v+=d:(h.write(i.indexOf(v),n),i.size()<4095&&(i.size()==1<<n&&(n+=1),i.add(v+d)),v=d)}return h.write(i.indexOf(v),n),h.write(e,n),h.flush(),l.toByteArray()},u=function(){var t={},r=0,e={add:function(n){if(e.contains(n))throw\"dup key:\"+n;t[n]=r,r+=1},size:function(){return r},indexOf:function(r){return t[r]},contains:function(r){return void 0!==t[r]}};return e};return i}(t,r),o=0;o<r;o+=1)for(var i=0;i<t;i+=1)n.setPixel(i,o,e(i,o));var a=D();n.write(a);for(var u=function(){var t=0,r=0,e=0,n=\"\",o={},i=function(t){n+=String.fromCharCode(a(63&t))},a=function(t){if(t<0);else{if(t<26)return 65+t;if(t<52)return t-26+97;if(t<62)return t-52+48;if(62==t)return 43;if(63==t)return 47}throw\"n:\"+t};return o.writeByte=function(n){for(t=t<<8|255&n,r+=8,e+=1;r>=6;)i(t>>>r-6),r-=6},o.flush=function(){if(r>0&&(i(t<<6-r),t=0,r=0),e%3!=0)for(var o=3-e%3,a=0;a<o;a+=1)n+=\"=\"},o.toString=function(){return n},o}(),f=a.toByteArray(),c=0;c<f.length;c+=1)u.writeByte(f[c]);return u.flush(),\"data:image/gif;base64,\"+u};return t}();qrcode.stringToBytesFuncs[\"UTF-8\"]=function(t){return function(t){for(var r=[],e=0;e<t.length;e++){var n=t.charCodeAt(e);n<128?r.push(n):n<2048?r.push(192|n>>6,128|63&n):n<55296||n>=57344?r.push(224|n>>12,128|n>>6&63,128|63&n):(e++,n=65536+((1023&n)<<10|1023&t.charCodeAt(e)),r.push(240|n>>18,128|n>>12&63,128|n>>6&63,128|63&n))}return r}(t)},function(t){\"function\"==typeof define&&define.amd?define([],t):\"object\"==typeof exports&&(module.exports=t())}((function(){return qrcode}));\n//# sourceMappingURL=/sm/26b4b0d0b1e283d6b3ec9857ac597d7a60c76ac17be1ef4c965f03086de426bb.map"
    "";

static void web_log_verbose(const junknas_config_t *config, const char *fmt, ...) {
    if (!config || !config->verbose) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

static int is_safe_relative(const char *path) {
    if (!path) return 0;
    if (path[0] == '/') return 0;
    if (strstr(path, "..")) return 0;
    return 1;
}

static int is_hex64(const char *hash) {
    if (!hash) return 0;
    if (strlen(hash) != 64) return 0;
    for (size_t i = 0; i < 64; i++) {
        char c = hash[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return 0;
        }
    }
    return 1;
}

static int chunk_path_for_hash(const char *data_dir, const char *hash, char *out, size_t out_len) {
    if (!data_dir || !hash || !out) return -1;
    if (!is_hex64(hash)) return -1;
    if (snprintf(out, out_len, "%s/.jnk/chunks/sha256/%c%c/%s",
                 data_dir, hash[0], hash[1], hash) >= (int)out_len) {
        return -1;
    }
    return 0;
}

static void send_all(int fd, const char *data) {
    if (!data) return;
    send(fd, data, strlen(data), 0);
}

static void send_status(int fd, int code, const char *message) {
    char buf[128];
    snprintf(buf, sizeof(buf), "HTTP/1.1 %d %s\r\nConnection: close\r\n\r\n", code, message);
    send_all(fd, buf);
}

static void send_text(int fd, int code, const char *body) {
    char header[256];
    size_t len = body ? strlen(body) : 0;
    snprintf(header, sizeof(header),
             "HTTP/1.1 %d OK\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
             code, len);
    send_all(fd, header);
    if (body) send(fd, body, len, 0);
}

static void send_json(int fd, int code, const char *body) {
    char header[256];
    size_t len = body ? strlen(body) : 0;
    snprintf(header, sizeof(header),
             "HTTP/1.1 %d OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
             code, len);
    send_all(fd, header);
    if (body) send(fd, body, len, 0);
}

static void send_html_header(int fd, const char *title) {
    char header[256];
    snprintf(header, sizeof(header),
             "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n");
    send_all(fd, header);
    send_all(fd, "<!doctype html><html><head><meta charset=\"utf-8\">");
    send_all(fd, "<title>");
    send_all(fd, title ? title : "junkNAS");
    send_all(fd, "</title></head><body>");
}

static void send_html_footer(int fd) {
    send_all(fd, "</body></html>");
}

static int parse_peer_json(cJSON *obj, junknas_wg_peer_t *peer) {
    if (!cJSON_IsObject(obj) || !peer) return -1;
    junknas_wg_peer_t out = {0};

    cJSON *pub = cJSON_GetObjectItemCaseSensitive(obj, "public_key");
    if (cJSON_IsString(pub) && pub->valuestring) {
        snprintf(out.public_key, sizeof(out.public_key), "%s", pub->valuestring);
    }
    cJSON *endpoint = cJSON_GetObjectItemCaseSensitive(obj, "endpoint");
    if (cJSON_IsString(endpoint) && endpoint->valuestring) {
        snprintf(out.endpoint, sizeof(out.endpoint), "%s", endpoint->valuestring);
    }
    cJSON *wg_ip = cJSON_GetObjectItemCaseSensitive(obj, "wg_ip");
    if (cJSON_IsString(wg_ip) && wg_ip->valuestring) {
        snprintf(out.wg_ip, sizeof(out.wg_ip), "%s", wg_ip->valuestring);
    }
    cJSON *keepalive = cJSON_GetObjectItemCaseSensitive(obj, "persistent_keepalive");
    if (cJSON_IsNumber(keepalive) && keepalive->valuedouble >= 0) {
        out.persistent_keepalive = (uint16_t)keepalive->valuedouble;
    }
    cJSON *web_port = cJSON_GetObjectItemCaseSensitive(obj, "web_port");
    if (cJSON_IsNumber(web_port) && web_port->valuedouble > 0 && web_port->valuedouble < 65536) {
        out.web_port = (uint16_t)web_port->valuedouble;
    }

    if (out.public_key[0] == '\0' || out.wg_ip[0] == '\0') return -1;
    *peer = out;
    return 0;
}

static cJSON *peer_to_json(const junknas_wg_peer_t *peer) {
    if (!peer) return NULL;
    cJSON *obj = cJSON_CreateObject();
    if (!obj) return NULL;
    cJSON_AddStringToObject(obj, "public_key", peer->public_key);
    cJSON_AddStringToObject(obj, "endpoint", peer->endpoint);
    cJSON_AddStringToObject(obj, "wg_ip", peer->wg_ip);
    cJSON_AddNumberToObject(obj, "persistent_keepalive", (double)peer->persistent_keepalive);
    cJSON_AddNumberToObject(obj, "web_port", (double)peer->web_port);
    return obj;
}

static cJSON *build_mesh_state_json(junknas_config_t *config) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    junknas_config_lock(config);
    if (strcmp(config->node_state, NODE_STATE_NODE) == 0) {
        cJSON_AddNumberToObject(root, "updated_at", (double)config->wg_peers_updated_at);
        cJSON_AddNumberToObject(root, "mounts_updated_at", (double)config->data_mount_points_updated_at);

        cJSON *self = cJSON_CreateObject();
        if (self) {
            cJSON_AddStringToObject(self, "public_key", config->wg.public_key);
            cJSON_AddStringToObject(self, "endpoint", config->wg.endpoint);
            cJSON_AddStringToObject(self, "wg_ip", config->wg.wg_ip);
            cJSON_AddNumberToObject(self, "web_port", (double)config->web_port);
            cJSON_AddNumberToObject(self, "persistent_keepalive", 0);
            cJSON_AddNumberToObject(self, "listen_port", (double)config->wg.listen_port);
            cJSON_AddItemToObject(root, "self", self);
        }

        cJSON *peers = cJSON_CreateArray();
        if (peers) {
            for (int i = 0; i < config->wg_peer_count; i++) {
                cJSON *peer = peer_to_json(&config->wg_peers[i]);
                if (peer) cJSON_AddItemToArray(peers, peer);
            }
            cJSON_AddItemToObject(root, "peers", peers);
        }

        cJSON *mounts = cJSON_CreateArray();
        if (mounts) {
            for (int i = 0; i < config->data_mount_point_count; i++) {
                cJSON_AddItemToArray(mounts, cJSON_CreateString(config->data_mount_points[i]));
            }
            cJSON_AddItemToObject(root, "mount_points", mounts);
        }
    } else {
        cJSON_AddNumberToObject(root, "updated_at", 0.0);
        cJSON_AddNumberToObject(root, "mounts_updated_at", 0.0);
    }
    junknas_config_unlock(config);
    return root;
}

static void respond_mesh_state(int fd, junknas_config_t *config) {
    cJSON *root = build_mesh_state_json(config);
    if (!root) {
        send_status(fd, 500, "Error");
        return;
    }

    char *printed = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!printed) {
        send_status(fd, 500, "Error");
        return;
    }
    send_json(fd, 200, printed);
    free(printed);
}

static int parse_endpoint(const char *endpoint, char *host, size_t host_len, uint16_t *port) {
    if (!endpoint || !host || !port) return -1;
    const char *colon = strrchr(endpoint, ':');
    if (!colon || colon == endpoint || *(colon + 1) == '\0') return -1;

    size_t hlen = (size_t)(colon - endpoint);
    if (hlen >= host_len) return -1;
    memcpy(host, endpoint, hlen);
    host[hlen] = '\0';

    char *end = NULL;
    long p = strtol(colon + 1, &end, 10);
    if (end == colon + 1 || *end != '\0' || p < 1 || p > 65535) return -1;
    *port = (uint16_t)p;
    return 0;
}

static int resolve_addr(const char *host, uint16_t port, int socktype,
                        struct sockaddr_storage *out, socklen_t *out_len) {
    if (!host || !out || !out_len) return -1;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = socktype;
    hints.ai_family = AF_UNSPEC;

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;
    if (!res) return -1;
    memcpy(out, res->ai_addr, res->ai_addrlen);
    *out_len = (socklen_t)res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

static int generate_wg_keypair(char *out_private, size_t private_len,
                               char *out_public, size_t public_len) {
    if (!out_private || !out_public || private_len < MAX_WG_KEY_LEN || public_len < MAX_WG_KEY_LEN) {
        return -1;
    }

    wg_key private_key;
    wg_key public_key;
    wg_key_b64_string private_b64;
    wg_key_b64_string public_b64;

    wg_generate_private_key(private_key);
    wg_generate_public_key(public_key, private_key);
    wg_key_to_base64(private_b64, private_key);
    wg_key_to_base64(public_b64, public_key);

    snprintf(out_private, private_len, "%s", private_b64);
    snprintf(out_public, public_len, "%s", public_b64);
    return 0;
}

static int allocate_peer_ip(const junknas_config_t *config, char *out, size_t out_len) {
    if (!config || !out || out_len < 16) return -1;

    uint8_t prefix[3] = {10, 99, 0};
    struct in_addr local_addr;
    if (inet_pton(AF_INET, config->wg.wg_ip, &local_addr) == 1) {
        uint32_t ip = ntohl(local_addr.s_addr);
        prefix[0] = (uint8_t)((ip >> 24) & 0xff);
        prefix[1] = (uint8_t)((ip >> 16) & 0xff);
        prefix[2] = (uint8_t)((ip >> 8) & 0xff);
    }

    bool used[255];
    memset(used, 0, sizeof(used));
    used[1] = true;

    if (inet_pton(AF_INET, config->wg.wg_ip, &local_addr) == 1) {
        uint32_t ip = ntohl(local_addr.s_addr);
        uint8_t host = (uint8_t)(ip & 0xff);
        if (host < sizeof(used)) {
            used[host] = true;
        }
    }

    for (int i = 0; i < config->wg_peer_count; i++) {
        struct in_addr peer_addr;
        if (inet_pton(AF_INET, config->wg_peers[i].wg_ip, &peer_addr) == 1) {
            uint32_t ip = ntohl(peer_addr.s_addr);
            uint8_t host = (uint8_t)(ip & 0xff);
            if (host < sizeof(used)) {
                used[host] = true;
            }
        }
    }

    for (uint8_t host = 2; host < 255; host++) {
        if (!used[host]) {
            snprintf(out, out_len, "%u.%u.%u.%u", prefix[0], prefix[1], prefix[2], host);
            return 0;
        }
    }

    return -1;
}

static int update_wg_peer_by_ip(junknas_config_t *config, const junknas_wg_peer_t *peer) {
    if (!config || !peer || peer->public_key[0] == '\0' || peer->wg_ip[0] == '\0') return -1;

    for (int i = 0; i < config->wg_peer_count; i++) {
        if (strcmp(config->wg_peers[i].wg_ip, peer->wg_ip) == 0) {
            config->wg_peers[i] = *peer;
            return 1;
        }
    }

    if (config->wg_peer_count >= MAX_WG_PEERS) return -1;
    config->wg_peers[config->wg_peer_count++] = *peer;
    return 1;
}

static char *http_request_body(const char *host, uint16_t port, const char *request,
                               const char *body, size_t body_len, int *out_status) {
    struct sockaddr_storage addr;
    socklen_t addr_len = 0;
    if (resolve_addr(host, port, SOCK_STREAM, &addr, &addr_len) != 0) return NULL;

    int fd = socket(addr.ss_family, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    if (connect(fd, (struct sockaddr *)&addr, addr_len) != 0) {
        close(fd);
        return NULL;
    }

    if (send(fd, request, strlen(request), 0) < 0) {
        close(fd);
        return NULL;
    }
    if (body && body_len > 0) {
        if (send(fd, body, body_len, 0) < 0) {
            close(fd);
            return NULL;
        }
    }

    char buf[4096];
    char header_buf[8192 + 1];
    size_t header_used = 0;
    int status = 0;
    int header_done = 0;
    char *out = NULL;
    size_t out_len = 0;

    while (1) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;

        if (!header_done) {
            size_t to_copy = (size_t)n;
            if (header_used + to_copy > sizeof(header_buf)) {
                to_copy = sizeof(header_buf) - header_used;
            }
            memcpy(header_buf + header_used, buf, to_copy);
            header_used += to_copy;

            char *header_end = NULL;
            for (size_t i = 0; i + 3 < header_used; i++) {
                if (header_buf[i] == '\r' && header_buf[i + 1] == '\n' &&
                    header_buf[i + 2] == '\r' && header_buf[i + 3] == '\n') {
                    header_end = header_buf + i + 4;
                    size_t header_len = i + 4;
                    if (header_len < sizeof(header_buf)) {
                        header_buf[header_len] = '\0';
                    } else {
                        header_buf[sizeof(header_buf) - 1] = '\0';
                    }
                    char *line_end = strstr(header_buf, "\r\n");
                    if (line_end) {
                        *line_end = '\0';
                        (void)sscanf(header_buf, "HTTP/%*s %d", &status);
                    }
                    header_done = 1;
                    size_t body_part = header_used - header_len;
                    if (body_part > 0) {
                        char *new_out = realloc(out, out_len + body_part + 1);
                        if (!new_out) break;
                        out = new_out;
                        memcpy(out + out_len, header_end, body_part);
                        out_len += body_part;
                        out[out_len] = '\0';
                    }
                    break;
                }
            }
        } else {
            char *new_out = realloc(out, out_len + (size_t)n + 1);
            if (!new_out) break;
            out = new_out;
            memcpy(out + out_len, buf, (size_t)n);
            out_len += (size_t)n;
            out[out_len] = '\0';
        }
    }

    close(fd);
    if (out_status) *out_status = status;
    if (!out) {
        out = calloc(1, 1);
    }
    return out;
}

static void respond_mesh_config(int fd, junknas_config_t *config) {
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        send_status(fd, 500, "Error");
        return;
    }

    junknas_config_lock(config);
    cJSON *self = cJSON_CreateObject();
    if (self) {
        cJSON_AddStringToObject(self, "public_key", config->wg.public_key);
        cJSON_AddStringToObject(self, "endpoint", config->wg.endpoint);
        cJSON_AddStringToObject(self, "wg_ip", config->wg.wg_ip);
        cJSON_AddNumberToObject(self, "listen_port", (double)config->wg.listen_port);
        cJSON_AddNumberToObject(self, "web_port", (double)config->web_port);
        cJSON_AddItemToObject(root, "self", self);
    }

    cJSON_AddStringToObject(root, "node_state", config->node_state);
    cJSON_AddNumberToObject(root, "bootstrap_peers_updated_at",
                            (double)config->bootstrap_peers_updated_at);
    cJSON *bootstrap = cJSON_CreateArray();
    if (bootstrap) {
        for (int i = 0; i < config->bootstrap_peer_count; i++) {
            cJSON_AddItemToArray(bootstrap, cJSON_CreateString(config->bootstrap_peers[i]));
        }
        cJSON_AddItemToObject(root, "bootstrap_peers", bootstrap);
    }

    cJSON_AddNumberToObject(root, "wg_peers_updated_at",
                            (double)config->wg_peers_updated_at);
    cJSON *peers = cJSON_CreateArray();
    if (peers) {
        for (int i = 0; i < config->wg_peer_count; i++) {
            cJSON *peer = peer_to_json(&config->wg_peers[i]);
            if (peer) cJSON_AddItemToArray(peers, peer);
        }
        cJSON_AddItemToObject(root, "wg_peers", peers);
    }
    junknas_config_unlock(config);

    char *printed = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!printed) {
        send_status(fd, 500, "Error");
        return;
    }
    send_json(fd, 200, printed);
    free(printed);
}

static const char *status_label(int status) {
    if (status > 0) return "connected";
    if (status == 0) return "unreachable";
    return "connecting";
}

static void mark_wg_peer_connecting(junknas_config_t *config, const char *public_key) {
    if (!config || !public_key || public_key[0] == '\0') return;
    for (int i = 0; i < config->wg_peer_count; i++) {
        if (strcmp(config->wg_peers[i].public_key, public_key) == 0) {
            config->wg_peer_status[i] = -1;
            return;
        }
    }
}

static void respond_mesh_status(int fd, junknas_config_t *config) {
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        send_status(fd, 500, "Error");
        return;
    }

    junknas_config_lock(config);
    int bootstrap_count = config->bootstrap_peer_count;
    int wg_count = config->wg_peer_count;
    int any_reachable = 0;
    for (int i = 0; i < bootstrap_count; i++) {
        if (config->bootstrap_peer_status[i] == 1) {
            any_reachable = 1;
            break;
        }
    }
    if (!any_reachable) {
        for (int i = 0; i < wg_count; i++) {
            if (config->wg_peer_status[i] == 1) {
                any_reachable = 1;
                break;
            }
        }
    }

    if (bootstrap_count == 0 && wg_count == 0) {
        cJSON_AddStringToObject(root, "role", "standalone");
    } else if (any_reachable) {
        cJSON_AddStringToObject(root, "role", "central");
    } else {
        cJSON_AddStringToObject(root, "role", "dead_end");
    }

    cJSON *bootstrap = cJSON_CreateArray();
    if (bootstrap) {
        for (int i = 0; i < bootstrap_count; i++) {
            cJSON *entry = cJSON_CreateObject();
            if (!entry) continue;
            cJSON_AddStringToObject(entry, "endpoint", config->bootstrap_peers[i]);
            cJSON_AddStringToObject(entry, "status", status_label(config->bootstrap_peer_status[i]));
            cJSON_AddItemToArray(bootstrap, entry);
        }
        cJSON_AddItemToObject(root, "bootstrap_peers", bootstrap);
    }

    cJSON *wg = cJSON_CreateArray();
    if (wg) {
        for (int i = 0; i < wg_count; i++) {
            cJSON *entry = cJSON_CreateObject();
            if (!entry) continue;
            cJSON_AddStringToObject(entry, "public_key", config->wg_peers[i].public_key);
            cJSON_AddStringToObject(entry, "wg_ip", config->wg_peers[i].wg_ip);
            cJSON_AddNumberToObject(entry, "web_port",
                                    (double)(config->wg_peers[i].web_port ? config->wg_peers[i].web_port
                                                                          : config->web_port));
            cJSON_AddStringToObject(entry, "status", status_label(config->wg_peer_status[i]));
            cJSON_AddItemToArray(wg, entry);
        }
        cJSON_AddItemToObject(root, "wg_peers", wg);
    }
    junknas_config_unlock(config);

    char *printed = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!printed) {
        send_status(fd, 500, "Error");
        return;
    }
    send_json(fd, 200, printed);
    free(printed);
}

static void respond_mesh_ui(int fd) {
    send_html_header(fd, "junkNAS mesh");
    send_all(fd,
             "<style>"
             "body{font-family:Arial,sans-serif;margin:20px;color:#222;}"
             "h1{margin-bottom:4px;} .status{padding:8px 12px;border-radius:6px;margin:10px 0;}"
             ".status.central{background:#e6f7ec;color:#126b2d;}"
             ".status.dead_end{background:#ffe8e8;color:#a60000;}"
             ".status.standalone{background:#eef2ff;color:#1e3a8a;}"
             "table{border-collapse:collapse;width:100%;margin-top:8px;}"
             "th,td{border:1px solid #ddd;padding:6px;text-align:left;}"
             "input{width:100%;box-sizing:border-box;}"
             "textarea{width:100%;box-sizing:border-box;}"
             ".mesh-join-grid{display:grid;grid-template-columns:180px 1fr;gap:12px;align-items:start;}"
             "#mesh-qr{border:1px solid #ddd;border-radius:6px;background:#fff;}"
             ".checkbox{display:flex;align-items:center;gap:8px;margin-top:8px;}"
             ".actions{margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;}"
             ".muted{color:#666;font-size:12px;}"
             ".badge{display:inline-block;padding:2px 6px;border-radius:4px;background:#eee;font-size:12px;}"
             ".badge.connected{background:#e6f7ec;color:#126b2d;}"
             ".badge.connecting{background:#fff4e5;color:#8a3b00;}"
             ".badge.unreachable{background:#ffe8e8;color:#a60000;}"
             ".remove-peer{background:#ffe8e8;border:1px solid #f5b5b5;border-radius:4px;color:#a60000;"
             "padding:4px 8px;cursor:pointer;}"
             ".remove-peer:hover{background:#ffd6d6;}"
             "</style>");
    send_all(fd, "<h1>junkNAS mesh settings</h1>");
    send_all(fd, "<div id=\"mesh-role\" class=\"status\">Checking mesh status…</div>");
    send_all(fd, "<section><h2>Local node</h2>"
                  "<label>Node state "
                  "<select id=\"node-state\">"
                  "<option value=\"node\">Node (hosts WG server)</option>"
                  "<option value=\"end\">End (no WG server)</option>"
                  "</select>"
                  "</label>"
                  "<div id=\"self-info\">Loading…</div></section>");
    send_all(fd, "<section id=\"sync-section\"><h2>Sync new mesh</h2>"
                  "<p>Generate a join config for a new peer and share it securely.</p>"
                  "<p id=\"sync-disabled\" class=\"muted\" style=\"display:none;\">"
                  "Sync config generation is disabled while this node is set to end.</p>"
                  "<div class=\"actions\">"
                  "<button id=\"sync-new\">Sync new mesh</button>"
                  "<button id=\"copy-join\" type=\"button\">Copy join config</button>"
                  "</div>"
                  "<div class=\"mesh-join-grid\">"
                  "<canvas id=\"mesh-qr\" width=\"180\" height=\"180\"></canvas>"
                  "<textarea id=\"join-config\" rows=\"7\" readonly></textarea>"
                  "</div></section>");
    send_all(fd, "<section><h2>Join mesh</h2>"
                  "<p>Paste a join config from another node to connect to its WireGuard interface.</p>"
                  "<textarea id=\"join-input\" rows=\"7\"></textarea>"
                  "<label class=\"checkbox\"><input type=\"checkbox\" id=\"dead-end\" checked>"
                  "This node is a dead end (no inbound NAT traversal).</label>"
                  "<div class=\"actions\"><button id=\"join-mesh\">Join mesh</button>"
                  "<span id=\"join-status\"></span></div></section>");
    send_all(fd, "<section><h2>WireGuard peers</h2>"
                  "<table id=\"wg-peers\">"
                  "<thead><tr>"
                  "<th>Public key</th><th>Endpoint</th>"
                  "<th>WG IP</th><th>Keepalive</th><th>Web port</th><th>Status</th><th>Actions</th>"
                  "</tr></thead><tbody></tbody></table></section>");
    send_all(fd, "<div class=\"actions\">"
                  "<button id=\"save-config\">Save changes</button>"
                  "<span id=\"save-status\"></span>"
                  "</div>");
    send_all(fd,
             "<script>"
             "const qrcodegen=function(){function e(e,t){this.modules=null,this.moduleCount=0,this.errorCorrectLevel=e,this.typeNumber=t}function t(e){this.mode=a.MODE_8BIT_BYTE,this.data=e,this.parsed=[];for(let t=0;t<e.length;t++){const r=e.charCodeAt(t);r<128?this.parsed.push(r):r<2048?(this.parsed.push(192|r>>6),this.parsed.push(128|63&r)):r<65536?(this.parsed.push(224|r>>12),this.parsed.push(128|r>>6&63),this.parsed.push(128|63&r)):(this.parsed.push(240|r>>18),this.parsed.push(128|r>>12&63),this.parsed.push(128|r>>6&63),this.parsed.push(128|63&r))}}const r={};r.QrCode=e,r.QrSegment=t;const a={};a.PAD0=236,a.PAD1=17,a.Ecc={LOW:1,MEDIUM:0,QUARTILE:3,HIGH:2},a.MODE_8BIT_BYTE=4,a.getBCHTypeInfo=function(e){let t=e<<10;for(;a.getBCHDigit(t)-a.getBCHDigit(1335)>=0;)t^=1335<<a.getBCHDigit(t)-a.getBCHDigit(1335);return(e<<10|t)^21522},a.getBCHTypeNumber=function(e){let t=e<<12;for(;a.getBCHDigit(t)-a.getBCHDigit(7973)>=0;)t^=7973<<a.getBCHDigit(t)-a.getBCHDigit(7973);return e<<12|t},a.getBCHDigit=function(e){let t=0;for(;e!=0;)t++,e>>=1;return t},a.getPatternPosition=function(e){return a.PATTERN_POSITION_TABLE[e-1]},a.getMask=function(e,t,r){switch(e){case 0:return(t+r)%2==0;case 1:return t%2==0;case 2:return r%3==0;case 3:return(t+r)%3==0;case 4:return(Math.floor(t/2)+Math.floor(r/3))%2==0;case 5:return t*r%2+t*r%3==0;case 6:return(t*r%2+t*r%3)%2==0;case 7:return(t*r%3+(t+r)%2)%2==0;default:throw new Error('bad maskPattern:'+e)}},a.getErrorCorrectPolynomial=function(e){let t=new i([1],0);for(let r=0;r<e;r++)t=t.multiply(new i([1,a.gexp(r)],0));return t},a.getLengthInBits=function(e,t){if(1<=t&&t<10)return 8;else if(t<27)return 16;else if(t<41)return 16;throw new Error('type:'+t)},a.getLostPoint=function(e){const t=e.moduleCount;let r=0;for(let a=0;a<t;a++)for(let i=0;i<t;i++){let n=0;const o=e.isDark(a,i);for(let e=-1;e<=1;e++)if(!(a+e<0||t<=a+e))for(let t=-1;t<=1;t++)if(!(i+t<0||t<=i+t)&&!(0==e&&0==t)&&o==e.isDark(a+e,i+t))n++;n>5&&(r+=3+n-5)}for(let a=0;a<t-1;a++)for(let i=0;i<t-1;i++){let n=0;e.isDark(a,i)&&n++,e.isDark(a+1,i)&&n++,e.isDark(a,i+1)&&n++,e.isDark(a+1,i+1)&&n++;(0==n||4==n)&&(r+=3)}for(let a=0;a<t;a++)for(let i=0;i<t-6;i++)e.isDark(a,i)&&!e.isDark(a,i+1)&&e.isDark(a,i+2)&&e.isDark(a,i+3)&&e.isDark(a,i+4)&&!e.isDark(a,i+5)&&e.isDark(a,i+6)&&(r+=40);for(let a=0;a<t;a++)for(let i=0;i<t-6;i++)e.isDark(i,a)&&!e.isDark(i+1,a)&&e.isDark(i+2,a)&&e.isDark(i+3,a)&&e.isDark(i+4,a)&&!e.isDark(i+5,a)&&e.isDark(i+6,a)&&(r+=40);let a=0;for(let r=0;r<t;r++)for(let i=0;i<t;i++)e.isDark(r,i)&&a++;return r+=10*Math.abs(100*a/t/t-50)/5},a.getRSBlocks=function(e,t){const r=a.RS_BLOCK_TABLE[4*(e-1)+t];if(void 0==r)throw new Error('bad rs block @ typeNumber:'+e+'/errorCorrectLevel:'+t);const i=r.length/3,n=[];for(let o=0;o<i;o++)for(let i=r[3*o+0],s=r[3*o+1],l=r[3*o+2],u=0;u<i;u++)n.push(new s(s,l));return n};const i=function(e,t){if(void 0==e.length)throw new Error(e.length+'/'+t);for(let t=0;t<e.length&&0==e[t];)t++;this.num=new Array(e.length-t+t);for(let r=0;r<e.length-t;r++)this.num[r]=e[r+t];this.shift=t};i.prototype={get:function(e){return this.num[e]},getLength:function(){return this.num.length},multiply:function(e){const t=new Array(this.getLength()+e.getLength()-1);for(let e=0;e<t.length;e++)t[e]=0;for(let r=0;r<this.getLength();r++)for(let a=0;a<e.getLength();a++)t[r+a]^=a.gexp(a.glog(this.get(r))+a.glog(e.get(a)));return new i(t,0)},mod:function(e){if(this.getLength()-e.getLength()<0)return this;const t=a.glog(this.get(0))-a.glog(e.get(0)),r=new Array(this.getLength());for(let e=0;e<this.getLength();e++)r[e]=this.get(e);for(let r=0;r<e.getLength();r++)r[r]^=a.gexp(a.glog(e.get(r))+t);return new i(r,0).mod(e)}};a.glog=function(e){if(e<1)throw new Error('glog('+e+')');return a.LOG_TABLE[e]};a.gexp=function(e){for(;e<0;)e+=255;for(;e>=256;)e-=255;return a.EXP_TABLE[e]};a.EXP_TABLE=new Array(256);a.LOG_TABLE=new Array(256);for(let e=0;e<8;e++)a.EXP_TABLE[e]=1<<e;for(let e=8;e<256;e++)a.EXP_TABLE[e]=a.EXP_TABLE[e-4]^a.EXP_TABLE[e-5]^a.EXP_TABLE[e-6]^a.EXP_TABLE[e-8];for(let e=0;e<255;e++)a.LOG_TABLE[a.EXP_TABLE[e]]=e;a.RS_BLOCK_TABLE=[1,26,19,1,26,16,1,26,13,1,26,9,1,44,34,1,44,28,1,44,22,1,44,16,1,70,55,1,70,44,2,35,17,2,35,13,1,100,80,2,50,32,2,50,24,4,25,9,1,134,108,2,67,43,2,33,15,2,33,11,2,86,68,4,43,27,4,43,19,4,43,15,2,98,78,4,49,31,2,32,14,4,39,13,4,121,97,2,60,38,4,40,18,2,30,14,4,40,18,4,36,16,2,146,116,4,58,36,4,36,16,4,46,20,4,40,18,2,86,68,4,69,43,6,43,19,2,44,18,2,100,80,4,50,32,6,50,24,4,25,9,2,134,108,4,67,43,6,33,15,2,33,11,4,146,116,6,58,36,2,36,16,4,46,20,6,40,18,4,50,32,4,50,24,2,25,9,4,121,97,4,60,38,6,40,18,2,30,14,2,146,116,6,58,36,4,36,16,6,46,20,4,40,18,4,61,47,4,47,27,6,38,22,2,29,14,4,58,40,2,47,26,4,37,22,4,29,14,4,147,116,6,58,36,2,36,16,7,46,20,6,40,18,4,77,59,8,47,27,8,38,22,4,29,14,5,65,52,10,39,24,8,37,22,8,29,14,6,139,106,6,69,43,4,43,19,4,33,11,7,79,61,6,47,27,8,38,22,2,31,14,5,73,55,6,46,20,10,39,24,4,37,22,8,29,14,13,145,112,8,58,36,4,36,16,11,46,20,6,40,18,5,56,44,10,47,27,10,38,22,4,29,14,12,92,68,12,58,36,4,36,16,11,46,20,4,40,18,7,42,32,14,47,27,14,38,22,6,29,14,4,133,104,16,58,36,2,36,16,11,46,20,4,40,18,9,74,56,16,47,27,16,38,22,4,29,14,2,131,104,8,59,37,6,37,16,11,46,20,6,40,18,2,93,69,17,47,27,22,45,20,13,28,10,4,107,81,4,65,40,14,39,18,16,49,24,4,36,16,2,116,92,6,58,36,14,37,16,16,46,20,6,40,18,4,121,97,14,47,27,16,38,22,4,29,14,6,114,88,12,60,37,6,41,17,10,46,20,6,40,18,7,122,98,14,48,27,11,39,22,7,30,14,4,117,91,10,61,37,16,38,17,16,46,20,6,40,18,7,126,100,12,47,27,16,38,22,4,29,14,6,100,80,10,54,27,14,41,18,2,32,14,9,143,108,14,61,37,10,39,18,12,46,20,6,40,18,7,110,84,12,48,27,18,44,20,8,31,14,5,127,98,14,62,37,10,40,18,16,46,20,6,40,18,8,139,105,14,47,27,22,45,20,8,30,14,8,107,81,12,51,27,12,41,18,12,45,20,2,32,14,10,97,74,14,48,27,18,45,20,8,31,14,3,120,90,14,52,27,20,38,18,10,46,20,6,40,18,7,142,107,10,53,27,18,43,20,10,31,14,4,88,67,20,51,27,20,41,18,4,47,20,6,40,18,2,116,86,10,46,27,28,45,20,14,31,14,4,82,62,14,48,27,28,44,20,2,32,14,4,137,104,14,53,27,18,42,20,4,33,14,13,115,87,8,40,27,12,31,20,8,41,14,4,80,58,14,50,27,20,47,20,4,32,14,5,118,89,16,55,27,20,45,20,8,33,14,5,80,60,12,46,27,24,42,20,8,32,14,11,115,87,12,45,27,22,40,20,4,33,14,5,102,78,12,48,27,28,44,20,4,31,14,8,132,96,14,54,27,32,43,20,4,32,14,5,94,70,20,51,27,28,45,20,4,31,14,10,117,87,14,45,27,24,42,20,10,32,14,10,88,64,14,50,27,24,39,20,8,32,14,4,130,98,18,54,27,16,43,20,4,32,14,14,115,85,16,46,27,24,41,20,6,32,14,5,94,70,26,50,27,16,40,20,6,32,14,8,126,96,18,53,27,16,43,20,10,32,14,10,91,67,26,50,27,18,40,20,8,32,14,8,127,96,22,53,27,22,43,20,12,32,14,5,100,75,24,49,27,30,40,20,8,32,14,11,112,84,24,51,27,18,42,20,4,32,14,5,103,77,28,49,27,28,40,20,12,32,14,5,117,87,26,52,27,22,42,20,4,32,14,11,112,84,26,50,27,30,41,20,8,32,14,4,119,89,26,49,27,24,41,20,8,32,14,6,106,80,24,51,27,28,42,20,12,32,14,4,113,85,28,53,27,22,43,20,4,32,14,5,129,96,28,52,27,32,42,20,8,32,14,4,120,90,28,50,27,24,42,20,8,32,14,12,119,87,28,54,27,24,43,20,8,32,14,4,113,85,30,53,27,24,43,20,12,32,14,7,110,86,28,54,27,32,43,20,12,32,14,12,119,87,28,50,27,24,43,20,12,32,14];a.PATTERN_POSITION_TABLE=[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],[6,28,50,72,94],[6,26,50,74,98],[6,30,54,78,102],[6,28,54,80,106],[6,32,58,84,110],[6,30,58,86,114],[6,34,62,90,118],[6,26,50,74,98,122],[6,30,54,78,102,126],[6,26,52,78,104,130],[6,30,56,82,108,134],[6,34,60,86,112,138],[6,30,58,86,114,142],[6,34,62,90,118,146],[6,30,54,78,102,126,150],[6,24,50,76,102,128,154],[6,28,54,80,106,132,158],[6,32,58,84,110,136,162],[6,26,54,82,110,138,166],[6,30,58,86,114,142,170]];e.prototype={addData:function(e){this.dataList||(this.dataList=[]);this.dataList.push(new t(e))},isDark:function(e,t){if(e<0||this.moduleCount<=e||t<0||this.moduleCount<=t)throw new Error(e+','+t);return this.modules[e][t]},getModuleCount:function(){return this.moduleCount},make:function(){if(this.typeNumber<1){let e=1;for(;e<40;e++){const t=a.getRSBlocks(e,this.errorCorrectLevel),r=new n;let i=0;for(let e=0;e<t.length;e++)i+=t[e].dataCount;for(let e=0;e<this.dataList.length;e++){const t=this.dataList[e];r.put(t.mode,4),r.put(t.parsed.length,a.getLengthInBits(t.mode,e)),t.write(r)}if(r.getLengthInBits()<=8*i)break}this.typeNumber=e}this.makeImpl(!1,this.getBestMaskPattern())},makeImpl:function(e,t){this.moduleCount=4*this.typeNumber+17,this.modules=new Array(this.moduleCount);for(let e=0;e<this.moduleCount;e++){this.modules[e]=new Array(this.moduleCount);for(let t=0;t<this.moduleCount;t++)this.modules[e][t]=null}this.setupPositionProbePattern(0,0),this.setupPositionProbePattern(this.moduleCount-7,0),this.setupPositionProbePattern(0,this.moduleCount-7),this.setupPositionAdjustPattern(),this.setupTimingPattern(),this.setupTypeInfo(e,t),this.typeNumber>=7&&this.setupTypeNumber(e);const r=this.createData(this.typeNumber,this.errorCorrectLevel);this.mapData(r,t)},setupPositionProbePattern:function(e,t){for(let r=-1;r<=7;r++)if(!(e+r<=-1||this.moduleCount<=e+r))for(let a=-1;a<=7;a++)t+a<=-1||this.moduleCount<=t+a||(r>=0&&r<=6&&(0==a||6==a)||a>=0&&a<=6&&(0==r||6==r)||r>=2&&r<=4&&a>=2&&a<=4?this.modules[e+r][t+a]=!0:this.modules[e+r][t+a]=!1)},getBestMaskPattern:function(){let e=0,t=0;for(let r=0;r<8;r++){this.makeImpl(!0,r);const a=a.getLostPoint(this);(0==r||e>a)&&(e=a,t=r)}return t},createData:function(e,t){const r=a.getRSBlocks(e,t),i=new n;for(let e=0;e<this.dataList.length;e++){const t=this.dataList[e];i.put(t.mode,4),i.put(t.parsed.length,a.getLengthInBits(t.mode,e)),t.write(i)}let s=0;for(let e=0;e<r.length;e++)s+=r[e].dataCount;if(i.getLengthInBits()>8*s)throw new Error('code length overflow. ('+i.getLengthInBits()+'>'+8*s+')');for(i.getLengthInBits()+4<=8*s&&i.put(0,4);i.getLengthInBits()%8!=0;)i.putBit(!1);for(;;){if(i.getLengthInBits()>=8*s)break;i.put(a.PAD0,8);if(i.getLengthInBits()>=8*s)break;i.put(a.PAD1,8)}return a.createBytes(i,r)},createBytes:function(e,t){let r=0,a=0,i=0;const n=new Array(t.length),o=new Array(t.length);for(let s=0;s<t.length;s++){const l=t[s].dataCount,u=t[s].totalCount-l;a=Math.max(a,l),i=Math.max(i,u),n[s]=new Array(l);for(let t=0;t<n[s].length;t++)n[s][t]=255&e.buffer[t+r];r+=l;const c=a.getErrorCorrectPolynomial(u),d=new i(n[s],c.getLength()-1).mod(c);o[s]=new Array(c.getLength()-1);for(let e=0;e<o[s].length;e++){const t=e+d.getLength()-o[s].length;o[s][e]=t>=0?d.get(t):0}}let s=0;const l=[];for(let e=0;e<a;e++)for(let t=0;t<n.length;t++)e<n[t].length&&(l[s++]=n[t][e]);for(let e=0;e<i;e++)for(let t=0;t<o.length;t++)e<o[t].length&&(l[s++]=o[t][e]);return l},setupTimingPattern:function(){for(let e=8;e<this.moduleCount-8;e++)null==this.modules[e][6]&&(this.modules[e][6]=e%2==0);for(let e=8;e<this.moduleCount-8;e++)null==this.modules[6][e]&&(this.modules[6][e]=e%2==0)},setupPositionAdjustPattern:function(){const e=a.getPatternPosition(this.typeNumber);for(let t=0;t<e.length;t++)for(let r=0;r<e.length;r++){const a=e[t],i=e[r];null==this.modules[a][i]&&this.setupPositionAdjustPatternAt(a,i)}},setupPositionAdjustPatternAt:function(e,t){for(let r=-2;r<=2;r++)for(let a=-2;a<=2;a++)this.modules[e+r][t+a]=r==-2||r==2||a==-2||a==2||0==r&&0==a},setupTypeNumber:function(e){const t=a.getBCHTypeNumber(this.typeNumber);for(let r=0;r<18;r++){const a=!e&&1==(t>>r&1);this.modules[Math.floor(r/3)][r%3+this.moduleCount-8-3]=a}for(let r=0;r<18;r++){const a=!e&&1==(t>>r&1);this.modules[r%3+this.moduleCount-8-3][Math.floor(r/3)]=a}},setupTypeInfo:function(e,t){const r=a.getBCHTypeInfo(this.errorCorrectLevel<<3|t);for(let a=0;a<15;a++){const t=!e&&1==(r>>a&1);a<6?this.modules[a][8]=t:a<8?this.modules[a+1][8]=t:this.modules[this.moduleCount-15+a][8]=t}for(let a=0;a<15;a++){const t=!e&&1==(r>>a&1);a<8?this.modules[8][this.moduleCount-a-1]=t:a<9?this.modules[8][15-a-1+1]=t:this.modules[8][15-a-1]=t}this.modules[this.moduleCount-8][8]=!e},mapData:function(e,t){let r=this.moduleCount-1,a=this.moduleCount-1,i=-1;for(let n=0;n<this.moduleCount-1;n++){for(let o=0;o<this.moduleCount;o++){const s=this.moduleCount-1-o;for(let o=0;o<2;o++)if(null==this.modules[r][s-o]){let l=!1;a<e.length&&(l=1==(e[a]>>>i&1));const u=a.getMask(t,r,s-o);u&&(l=!l),this.modules[r][s-o]=l,i--;if(-1==i){a++,i=7}}}r+=i==1?-1:1,i=-i}}};const n=function(){this.buffer=[];this.length=0};n.prototype={get:function(e){const t=Math.floor(e/8);return 1==(this.buffer[t]>>>7-e%8&1)},put:function(e,t){for(let r=0;r<t;r++)this.putBit(1==(e>>>t-r-1&1))},getLengthInBits:function(){return this.length},putBit:function(e){const t=Math.floor(this.length/8);this.buffer.length<=t&&this.buffer.push(0),e&&(this.buffer[t]|=128>>>this.length%8),this.length++}};t.prototype={write:function(e){for(let t=0;t<this.parsed.length;t++)e.put(this.parsed[t],8)}};return r}();"
             "const wgPeers = [];"
             "const statusMap = {wg:[]};"
             "let selfEndpoint = '';"
             "const escapeHtml = (text) => text.replace(/[&<>\"']/g, (c) => ({\"&\":\"&amp;\",\"<\":\"&lt;\",\">\":\"&gt;\",\"\\\"\":\"&quot;\",\"'\":\"&#39;\"}[c]));"
             "function renderQr(text){"
             "const canvas=document.getElementById('mesh-qr');"
             "const ctx=canvas.getContext('2d');"
             "ctx.clearRect(0,0,canvas.width,canvas.height);"
             "if(!text){return;}"
             "const qr=new qrcodegen.QrCode(0,0);"
             "qr.addData(text);"
             "qr.make();"
             "const size=qr.getModuleCount();"
             "const scale=Math.floor(Math.min(canvas.width,canvas.height)/size);"
             "const offset=Math.floor((canvas.width-size*scale)/2);"
             "ctx.fillStyle='#fff';"
             "ctx.fillRect(0,0,canvas.width,canvas.height);"
             "ctx.fillStyle='#000';"
             "for(let y=0;y<size;y++){"
             "for(let x=0;x<size;x++){"
             "if(qr.isDark(y,x)){"
             "ctx.fillRect(offset+x*scale,offset+y*scale,scale,scale);"
             "}"
             "}"
             "}"
             "}"
             "function renderWgPeers(){"
             "const tbody=document.querySelector('#wg-peers tbody');"
             "tbody.innerHTML='';"
             "wgPeers.forEach((peer,index)=>{"
             "const row=document.createElement('tr');"
             "const status=statusMap.wg[index]||'connecting';"
             "const statusClass=status.replace(/[^a-z0-9_-]/gi,'-');"
             "row.innerHTML=`"
             "<td>${escapeHtml(peer.public_key||'')}</td>"
             "<td>${escapeHtml(peer.endpoint||'')}</td>"
             "<td>${escapeHtml(peer.wg_ip||'')}</td>"
             "<td>${escapeHtml(String(peer.persistent_keepalive||''))}</td>"
             "<td>${escapeHtml(String(peer.web_port||''))}</td>"
             "<td><span class='badge ${statusClass}'>${escapeHtml(status)}</span></td>"
             "<td><button class='remove-peer' data-index='${index}'>Remove</button></td>`;"
             "tbody.appendChild(row);"
             "});"
             "}"
             "function toggleNodeStateUI(){"
             "const nodeState=document.getElementById('node-state').value||'node';"
             "const isEnd=nodeState==='end';"
             "const syncDisabled=document.getElementById('sync-disabled');"
             "const syncNew=document.getElementById('sync-new');"
             "const copyJoin=document.getElementById('copy-join');"
             "const joinConfig=document.getElementById('join-config');"
             "syncDisabled.style.display=isEnd?'block':'none';"
             "syncNew.disabled=isEnd;"
             "copyJoin.disabled=isEnd;"
             "joinConfig.disabled=isEnd;"
             "if(isEnd){"
             "joinConfig.value='';"
             "renderQr('');"
             "}"
             "}"
             "async function loadConfig(){"
             "const res=await fetch('/mesh/config');"
             "const data=await res.json();"
             "document.getElementById('node-state').value=data.node_state||'node';"
             "const self=data.self||{};"
             "selfEndpoint=self.endpoint||'';"
             "document.getElementById('self-info').innerHTML=`"
             "<div><strong>Public key:</strong> ${escapeHtml(self.public_key||'')}</div>"
             "<div><strong>WG IP:</strong> ${escapeHtml(self.wg_ip||'')}</div>"
             "<div><strong>Endpoint:</strong> ${escapeHtml(self.endpoint||'')}</div>"
             "<div><strong>WireGuard port:</strong> ${escapeHtml(String(self.listen_port||''))}</div>"
             "<div><strong>Web port:</strong> ${escapeHtml(String(self.web_port||''))}</div>`;"
             "toggleNodeStateUI();"
             "wgPeers.length=0;"
             "(data.wg_peers||[]).forEach(peer=>wgPeers.push(peer));"
             "await loadStatus();"
             "renderWgPeers();"
             "}"
             "async function loadStatus(){"
             "const res=await fetch('/mesh/status');"
             "const data=await res.json();"
             "const role=data.role||'unknown';"
             "const statusBox=document.getElementById('mesh-role');"
             "statusBox.className='status '+role;"
             "if(role==='dead_end'){"
             "statusBox.textContent='This node is a dead end (no reachable peers).';"
             "}else if(role==='central'){"
             "statusBox.textContent='This node is central (reachable peers detected).';"
             "}else if(role==='standalone'){"
             "statusBox.textContent='Standalone mesh (no peers configured).';"
             "}else{"
             "statusBox.textContent='Mesh status unavailable.';"
             "}"
             "statusMap.wg=(data.wg_peers||[]).map(p=>p.status);"
             "}"
             "document.getElementById('node-state').addEventListener('change',()=>{"
             "toggleNodeStateUI();"
             "});"
             "document.querySelector('#wg-peers tbody').addEventListener('click',(event)=>{"
             "const target=event.target;"
             "if(!target.classList.contains('remove-peer')){return;}"
             "const index=parseInt(target.dataset.index,10);"
             "if(Number.isNaN(index)){return;}"
             "wgPeers.splice(index,1);"
             "statusMap.wg.splice(index,1);"
             "renderWgPeers();"
             "});"
             "document.getElementById('save-config').addEventListener('click',async()=>{"
             "const nodeState=document.getElementById('node-state').value||'node';"
             "const res=await fetch('/mesh/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({wg_peers:wgPeers,node_state:nodeState})});"
             "const msg=document.getElementById('save-status');"
             "if(res.ok){"
             "msg.textContent='Saved.';"
             "await loadConfig();"
             "}else{"
             "msg.textContent='Save failed.';"
             "}"
             "});"
             "document.getElementById('sync-new').addEventListener('click',async()=>{"
             "const res=await fetch('/mesh/bootstrap',{method:'POST'});"
             "const msg=document.getElementById('save-status');"
             "if(res.ok){"
             "const data=await res.json();"
             "const text=JSON.stringify(data, null, 2);"
             "document.getElementById('join-config').value=text;"
             "renderQr(text);"
             "msg.textContent='Join config generated.';"
             "}else{"
             "msg.textContent='Failed to generate join config.';"
             "}"
             "});"
             "document.getElementById('copy-join').addEventListener('click',async()=>{"
             "const text=document.getElementById('join-config').value;"
             "if(!text){return;}"
             "if(navigator.clipboard&&navigator.clipboard.writeText){"
             "try{await navigator.clipboard.writeText(text);}catch(e){}}"
             "});"
             "document.getElementById('join-mesh').addEventListener('click',async()=>{"
             "const msg=document.getElementById('join-status');"
             "msg.textContent='';"
             "let configObj=null;"
             "try{configObj=JSON.parse(document.getElementById('join-input').value);}catch(e){"
             "msg.textContent='Join config is not valid JSON.';return;}"
             "const allowAlternate=!document.getElementById('dead-end').checked;"
             "const res=await fetch('/mesh/join',{method:'POST',headers:{'Content-Type':'application/json'},"
             "body:JSON.stringify({join_config:configObj,allow_alternate:allowAlternate,peer_endpoint:selfEndpoint})});"
             "if(res.ok){"
             "msg.textContent='Join request submitted.';"
             "await loadConfig();"
             "await loadStatus();"
             "}else{"
             "msg.textContent='Join failed.';"
             "}"
             "});"
             "loadConfig();"
             "</script>");
    send_html_footer(fd);
}

static int mesh_mount_points_equal(const junknas_config_t *config, cJSON *mounts) {
    if (!config || !cJSON_IsArray(mounts)) return 0;

    int n = cJSON_GetArraySize(mounts);
    if (n != config->data_mount_point_count) return 0;

    for (int i = 0; i < n; i++) {
        cJSON *entry = cJSON_GetArrayItem(mounts, i);
        if (!cJSON_IsString(entry) || !entry->valuestring) return 0;
        if (strcmp(config->data_mount_points[i], entry->valuestring) != 0) return 0;
    }

    return 1;
}

static int merge_mesh_payload(junknas_config_t *config, const char *payload) {
    if (!payload) return -1;
    cJSON *root = cJSON_Parse(payload);
    if (!root) return -1;

    int peers_changed = 0;
    int mounts_changed = 0;
    time_t now = time(NULL);

    junknas_config_lock(config);
    const char *local_pub = config->wg.public_key;

    cJSON *self = cJSON_GetObjectItemCaseSensitive(root, "self");
    if (cJSON_IsObject(self)) {
        junknas_wg_peer_t peer = {0};
        if (parse_peer_json(self, &peer) == 0) {
            if (local_pub[0] == '\0' || strcmp(local_pub, peer.public_key) != 0) {
                int rc = junknas_config_upsert_wg_peer(config, &peer);
                if (rc == 1) peers_changed = 1;
            }
        }
    }

    cJSON *peers = cJSON_GetObjectItemCaseSensitive(root, "peers");
    if (cJSON_IsArray(peers)) {
        int n = cJSON_GetArraySize(peers);
        for (int i = 0; i < n; i++) {
            cJSON *entry = cJSON_GetArrayItem(peers, i);
            junknas_wg_peer_t peer = {0};
            if (parse_peer_json(entry, &peer) != 0) continue;
            if (local_pub[0] != '\0' && strcmp(local_pub, peer.public_key) == 0) continue;
            int rc = junknas_config_upsert_wg_peer(config, &peer);
            if (rc == 1) peers_changed = 1;
        }
    }

    cJSON *mounts_updated = cJSON_GetObjectItemCaseSensitive(root, "mounts_updated_at");
    uint64_t remote_mounts_updated = 0;
    if (cJSON_IsNumber(mounts_updated) && mounts_updated->valuedouble >= 0) {
        remote_mounts_updated = (uint64_t)mounts_updated->valuedouble;
    }
    if (remote_mounts_updated >= config->data_mount_points_updated_at) {
        cJSON *mounts = cJSON_GetObjectItemCaseSensitive(root, "mount_points");
        if (cJSON_IsArray(mounts)) {
            int same = mesh_mount_points_equal(config, mounts);
            if (!same) {
                config->data_mount_point_count = 0;
                int n = cJSON_GetArraySize(mounts);
                for (int i = 0; i < n && config->data_mount_point_count < MAX_DATA_MOUNT_POINTS; i++) {
                    cJSON *entry = cJSON_GetArrayItem(mounts, i);
                    if (cJSON_IsString(entry) && entry->valuestring) {
                        (void)junknas_config_add_data_mount_point(config, entry->valuestring);
                    }
                }
                mounts_changed = 1;
            }
            if (remote_mounts_updated > config->data_mount_points_updated_at) {
                config->data_mount_points_updated_at = remote_mounts_updated;
                mounts_changed = 1;
            }
        }
    }

    if (peers_changed) {
        config->wg_peers_updated_at = (uint64_t)now;
    }
    if (peers_changed || mounts_changed) {
        (void)junknas_config_save(config, config->config_file_path);
    }
    junknas_config_unlock(config);

    cJSON_Delete(root);
    return (peers_changed || mounts_changed) ? 1 : 0;
}

static int update_mesh_config(junknas_config_t *config, const char *payload) {
    if (!payload) return -1;
    cJSON *root = cJSON_Parse(payload);
    if (!root) return -1;

    junknas_wg_peer_t peers[MAX_WG_PEERS];
    int peer_count = 0;
    int has_wg_peers = 0;

    cJSON *peer_arr = cJSON_GetObjectItemCaseSensitive(root, "wg_peers");
    if (cJSON_IsArray(peer_arr)) {
        has_wg_peers = 1;
        int n = cJSON_GetArraySize(peer_arr);
        for (int i = 0; i < n && peer_count < MAX_WG_PEERS; i++) {
            cJSON *entry = cJSON_GetArrayItem(peer_arr, i);
            junknas_wg_peer_t peer = {0};
            if (parse_peer_json(entry, &peer) == 0) {
                peers[peer_count++] = peer;
            }
        }
    }

    char bootstrap[MAX_BOOTSTRAP_PEERS][MAX_ENDPOINT_LEN];
    int bootstrap_count = 0;
    cJSON *bootstrap_arr = cJSON_GetObjectItemCaseSensitive(root, "bootstrap_peers");
    if (cJSON_IsArray(bootstrap_arr)) {
        int n = cJSON_GetArraySize(bootstrap_arr);
        for (int i = 0; i < n && bootstrap_count < MAX_BOOTSTRAP_PEERS; i++) {
            cJSON *entry = cJSON_GetArrayItem(bootstrap_arr, i);
            if (cJSON_IsString(entry) && entry->valuestring) {
                char host[MAX_ENDPOINT_LEN];
                uint16_t port = 0;
                if (parse_endpoint(entry->valuestring, host, sizeof(host), &port) == 0) {
                    snprintf(bootstrap[bootstrap_count], sizeof(bootstrap[bootstrap_count]),
                             "%s", entry->valuestring);
                    bootstrap_count++;
                } else {
                    cJSON_Delete(root);
                    return -1;
                }
            }
        }
    }

    time_t now = time(NULL);
    junknas_config_lock(config);
    config->bootstrap_peer_count = 0;
    for (int i = 0; i < bootstrap_count; i++) {
        snprintf(config->bootstrap_peers[config->bootstrap_peer_count],
                 sizeof(config->bootstrap_peers[config->bootstrap_peer_count]),
                 "%s", bootstrap[i]);
        config->bootstrap_peer_status[config->bootstrap_peer_count] = -1;
        config->bootstrap_peer_count++;
    }
    config->bootstrap_peers_updated_at = (uint64_t)now;

    if (has_wg_peers) {
        (void)junknas_config_set_wg_peers(config, peers, peer_count);
        for (int i = 0; i < config->wg_peer_count; i++) {
            config->wg_peer_status[i] = -1;
        }
        config->wg_peers_updated_at = (uint64_t)now;
    }

    cJSON *node_state = cJSON_GetObjectItemCaseSensitive(root, "node_state");
    if (cJSON_IsString(node_state) && node_state->valuestring &&
        (strcmp(node_state->valuestring, NODE_STATE_NODE) == 0 ||
         strcmp(node_state->valuestring, NODE_STATE_END) == 0)) {
        snprintf(config->node_state, sizeof(config->node_state), "%s", node_state->valuestring);
    }
    (void)junknas_config_save(config, config->config_file_path);
    junknas_config_unlock(config);

    cJSON_Delete(root);
    return 0;
}

static int respond_mesh_bootstrap(int fd, junknas_config_t *config) {
    if (!config) return -1;
    if (strcmp(config->node_state, NODE_STATE_END) == 0) {
        send_status(fd, 403, "Forbidden");
        return -1;
    }
    if (junknas_config_ensure_wg_keys(config) != 0) {
        send_status(fd, 500, "Error");
        return -1;
    }

    char peer_private[MAX_WG_KEY_LEN];
    char peer_public[MAX_WG_KEY_LEN];
    char peer_wg_ip[16];
    if (generate_wg_keypair(peer_private, sizeof(peer_private), peer_public, sizeof(peer_public)) != 0 ||
        allocate_peer_ip(config, peer_wg_ip, sizeof(peer_wg_ip)) != 0) {
        send_status(fd, 500, "Error");
        return -1;
    }

    char server_public[MAX_WG_KEY_LEN];
    char server_endpoint[MAX_ENDPOINT_LEN];
    char server_wg_ip[16];
    uint16_t server_web_port = DEFAULT_WEB_PORT;

    time_t now = time(NULL);
    junknas_config_lock(config);
    snprintf(server_public, sizeof(server_public), "%s", config->wg.public_key);
    snprintf(server_endpoint, sizeof(server_endpoint), "%s", config->wg.endpoint);
    snprintf(server_wg_ip, sizeof(server_wg_ip), "%s", config->wg.wg_ip);
    server_web_port = config->web_port;

    junknas_wg_peer_t peer = {0};
    snprintf(peer.public_key, sizeof(peer.public_key), "%s", peer_public);
    snprintf(peer.wg_ip, sizeof(peer.wg_ip), "%s", peer_wg_ip);
    peer.web_port = 0;
    int upserted = junknas_config_upsert_wg_peer(config, &peer);
    if (upserted < 0) {
        junknas_config_unlock(config);
        send_status(fd, 400, "Bad Request");
        return -1;
    }
    if (upserted > 0) {
        mark_wg_peer_connecting(config, peer_public);
    }
    config->wg_peers_updated_at = (uint64_t)now;
    (void)junknas_config_save(config, config->config_file_path);
    junknas_config_unlock(config);

    if (server_endpoint[0] == '\0') {
        web_log_verbose(config, "mesh: issuing join config without server endpoint");
    }
    web_log_verbose(config, "mesh: issued join config for peer %s", peer_wg_ip);

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        send_status(fd, 500, "Error");
        return -1;
    }
    cJSON_AddStringToObject(root, "peer_private_key", peer_private);
    cJSON_AddStringToObject(root, "peer_public_key", peer_public);
    cJSON_AddStringToObject(root, "peer_wg_ip", peer_wg_ip);
    cJSON_AddStringToObject(root, "server_public_key", server_public);
    cJSON_AddStringToObject(root, "server_endpoint", server_endpoint);
    cJSON_AddStringToObject(root, "server_wg_ip", server_wg_ip);
    cJSON_AddNumberToObject(root, "server_web_port", (double)server_web_port);

    char *printed = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!printed) {
        send_status(fd, 500, "Error");
        return -1;
    }
    send_json(fd, 200, printed);
    free(printed);
    return 0;
}

static int respond_mesh_alternate(int fd, junknas_config_t *config, const char *payload) {
    if (!config || !payload) return -1;
    cJSON *root = cJSON_Parse(payload);
    if (!root) {
        send_status(fd, 400, "Bad Request");
        return -1;
    }

    cJSON *wg_ip = cJSON_GetObjectItemCaseSensitive(root, "wg_ip");
    cJSON *public_key = cJSON_GetObjectItemCaseSensitive(root, "public_key");
    if (!cJSON_IsString(wg_ip) || !cJSON_IsString(public_key)) {
        cJSON_Delete(root);
        send_status(fd, 400, "Bad Request");
        return -1;
    }

    junknas_wg_peer_t peer = {0};
    snprintf(peer.wg_ip, sizeof(peer.wg_ip), "%s", wg_ip->valuestring);
    snprintf(peer.public_key, sizeof(peer.public_key), "%s", public_key->valuestring);

    cJSON *endpoint = cJSON_GetObjectItemCaseSensitive(root, "endpoint");
    if (cJSON_IsString(endpoint) && endpoint->valuestring) {
        snprintf(peer.endpoint, sizeof(peer.endpoint), "%s", endpoint->valuestring);
    }
    cJSON *web_port = cJSON_GetObjectItemCaseSensitive(root, "web_port");
    if (cJSON_IsNumber(web_port) && web_port->valuedouble > 0) {
        peer.web_port = (uint16_t)web_port->valuedouble;
    }

    time_t now = time(NULL);
    junknas_config_lock(config);
    int rc = update_wg_peer_by_ip(config, &peer);
    if (rc < 0) {
        junknas_config_unlock(config);
        cJSON_Delete(root);
        send_status(fd, 400, "Bad Request");
        return -1;
    }
    config->wg_peers_updated_at = (uint64_t)now;
    (void)junknas_config_save(config, config->config_file_path);
    junknas_config_unlock(config);

    web_log_verbose(config, "mesh: updated alternate peer %s", peer.wg_ip);

    cJSON_Delete(root);
    send_json(fd, 200, "{\"status\":\"ok\"}");
    return 0;
}

static int respond_mesh_join(int fd, junknas_config_t *config, const char *payload) {
    if (!config || !payload) return -1;
    cJSON *root = cJSON_Parse(payload);
    if (!root) {
        send_status(fd, 400, "Bad Request");
        return -1;
    }

    cJSON *join = cJSON_GetObjectItemCaseSensitive(root, "join_config");
    if (!cJSON_IsObject(join)) {
        cJSON_Delete(root);
        send_status(fd, 400, "Bad Request");
        return -1;
    }

    cJSON *peer_private = cJSON_GetObjectItemCaseSensitive(join, "peer_private_key");
    cJSON *peer_wg_ip = cJSON_GetObjectItemCaseSensitive(join, "peer_wg_ip");
    cJSON *server_public = cJSON_GetObjectItemCaseSensitive(join, "server_public_key");
    cJSON *server_endpoint = cJSON_GetObjectItemCaseSensitive(join, "server_endpoint");
    cJSON *server_wg_ip = cJSON_GetObjectItemCaseSensitive(join, "server_wg_ip");
    cJSON *server_web_port = cJSON_GetObjectItemCaseSensitive(join, "server_web_port");

    if (!cJSON_IsString(peer_private) || !cJSON_IsString(peer_wg_ip) ||
        !cJSON_IsString(server_public) || !cJSON_IsString(server_wg_ip)) {
        cJSON_Delete(root);
        send_status(fd, 400, "Bad Request");
        return -1;
    }

    const char *endpoint_value = "";
    if (cJSON_IsString(server_endpoint) && server_endpoint->valuestring) {
        endpoint_value = server_endpoint->valuestring;
    }
    if (endpoint_value[0] == '\0') {
        web_log_verbose(config, "mesh: join config missing server endpoint");
    }

    uint16_t web_port = DEFAULT_WEB_PORT;
    if (cJSON_IsNumber(server_web_port) && server_web_port->valuedouble > 0) {
        web_port = (uint16_t)server_web_port->valuedouble;
    }

    cJSON *allow_alt = cJSON_GetObjectItemCaseSensitive(root, "allow_alternate");
    int allow_alternate = cJSON_IsBool(allow_alt) ? cJSON_IsTrue(allow_alt) : 0;
    const char *peer_endpoint = "";
    cJSON *peer_endpoint_json = cJSON_GetObjectItemCaseSensitive(root, "peer_endpoint");
    if (cJSON_IsString(peer_endpoint_json) && peer_endpoint_json->valuestring) {
        peer_endpoint = peer_endpoint_json->valuestring;
    }
    web_log_verbose(config,
                    "mesh: join request parsed (peer_wg_ip=%s server_wg_ip=%s endpoint=%s web_port=%u allow_alternate=%d)",
                    peer_wg_ip->valuestring,
                    server_wg_ip->valuestring,
                    endpoint_value[0] ? endpoint_value : "(none)",
                    web_port,
                    allow_alternate);

    wg_key private_key;
    if (wg_key_from_base64(private_key, peer_private->valuestring) != 0) {
        cJSON_Delete(root);
        send_status(fd, 400, "Bad Request");
        return -1;
    }
    wg_key public_key;
    wg_key_b64_string public_b64;
    wg_generate_public_key(public_key, private_key);
    wg_key_to_base64(public_b64, public_key);
    web_log_verbose(config, "mesh: join keys validated for %s", peer_wg_ip->valuestring);

    time_t now = time(NULL);
    junknas_config_lock(config);
    snprintf(config->wg.private_key, sizeof(config->wg.private_key), "%s", peer_private->valuestring);
    snprintf(config->wg.public_key, sizeof(config->wg.public_key), "%s", public_b64);
    snprintf(config->wg.wg_ip, sizeof(config->wg.wg_ip), "%s", peer_wg_ip->valuestring);

    junknas_wg_peer_t server_peer = {0};
    snprintf(server_peer.public_key, sizeof(server_peer.public_key), "%s", server_public->valuestring);
    snprintf(server_peer.endpoint, sizeof(server_peer.endpoint), "%s", endpoint_value);
    snprintf(server_peer.wg_ip, sizeof(server_peer.wg_ip), "%s", server_wg_ip->valuestring);
    server_peer.web_port = web_port;
    int upserted = junknas_config_upsert_wg_peer(config, &server_peer);
    if (upserted < 0) {
        junknas_config_unlock(config);
        cJSON_Delete(root);
        send_status(fd, 400, "Bad Request");
        return -1;
    }
    if (upserted > 0) {
        mark_wg_peer_connecting(config, server_peer.public_key);
    }
    config->wg_peers_updated_at = (uint64_t)now;
    (void)junknas_config_save(config, config->config_file_path);
    junknas_config_unlock(config);

    web_log_verbose(config, "mesh: join config saved (upserted=%d)", upserted);
    web_log_verbose(config, "mesh: joined via %s", server_peer.wg_ip);

    if (allow_alternate) {
        web_log_verbose(config, "mesh: alternate join enabled; generating alternate keypair");
        char alternate_private[MAX_WG_KEY_LEN];
        char alternate_public[MAX_WG_KEY_LEN];
        if (generate_wg_keypair(alternate_private, sizeof(alternate_private),
                                alternate_public, sizeof(alternate_public)) == 0) {
            junknas_config_lock(config);
            snprintf(config->wg.private_key, sizeof(config->wg.private_key), "%s", alternate_private);
            snprintf(config->wg.public_key, sizeof(config->wg.public_key), "%s", alternate_public);
            config->wg_peers_updated_at = (uint64_t)time(NULL);
            (void)junknas_config_save(config, config->config_file_path);
            junknas_config_unlock(config);

            char host[MAX_ENDPOINT_LEN];
            uint16_t port = 0;
            if (parse_endpoint(endpoint_value, host, sizeof(host), &port) == 0) {
                (void)port;
                cJSON *alt = cJSON_CreateObject();
                if (alt) {
                    cJSON_AddStringToObject(alt, "wg_ip", peer_wg_ip->valuestring);
                    cJSON_AddStringToObject(alt, "public_key", alternate_public);
                    cJSON_AddStringToObject(alt, "endpoint", peer_endpoint);
                    cJSON_AddNumberToObject(alt, "web_port", (double)config->web_port);
                    char *alt_payload = cJSON_PrintUnformatted(alt);
                    cJSON_Delete(alt);
                    if (alt_payload) {
                        char request[512];
                        size_t payload_len = strlen(alt_payload);
                        snprintf(request, sizeof(request),
                                 "POST /mesh/alternate HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n",
                                 host, payload_len);
                        int status = 0;
                        char *body = http_request_body(host, web_port, request, alt_payload, payload_len, &status);
                        free(alt_payload);
                        if (body) free(body);
                        web_log_verbose(config, "mesh: alternate update %s (status %d)",
                                        status >= 200 && status < 300 ? "sent" : "failed", status);
                    }
                }
            } else {
                web_log_verbose(config, "mesh: alternate update skipped (no server endpoint)");
            }
        }
    }

    cJSON_Delete(root);
    send_json(fd, 200, "{\"status\":\"ok\"}");
    return 0;
}

static int sync_mesh_with_peer(junknas_config_t *config, const char *endpoint, const char *payload) {
    char host[MAX_ENDPOINT_LEN];
    uint16_t port = 0;
    if (parse_endpoint(endpoint, host, sizeof(host), &port) != 0) return -1;

    size_t payload_len = strlen(payload);
    char request[512];
    snprintf(request, sizeof(request),
             "POST /mesh/peers HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n",
             host, payload_len);

    int status = 0;
    char *body = http_request_body(host, port, request, payload, payload_len, &status);
    if (!body) return -1;

    if (status >= 200 && status < 300) {
        if (body[0] != '\0') {
            (void)merge_mesh_payload(config, body);
        }
        free(body);
        return 0;
    }

    free(body);
    return -1;
}

static void respond_mount_listing(int fd, junknas_config_t *config, const char *rel_path) {
    char full_path[MAX_PATH_LEN];
    if (rel_path && rel_path[0] != '\0') {
        snprintf(full_path, sizeof(full_path), "%s/%s", config->mount_point, rel_path);
    } else {
        snprintf(full_path, sizeof(full_path), "%s", config->mount_point);
    }

    DIR *dir = opendir(full_path);
    if (!dir) {
        send_status(fd, 404, "Not Found");
        return;
    }

    send_html_header(fd, "junkNAS fileshare");
    send_all(fd, "<h1>junkNAS fileshare</h1>");
    send_all(fd, "<p><a href=\"/mesh/ui\">Mesh settings</a></p>");
    send_all(fd, "<p>Mount point: ");
    send_all(fd, config->mount_point);
    send_all(fd, "</p>");

    if (config->data_mount_point_count > 0) {
        char stamp[64];
        snprintf(stamp, sizeof(stamp), "%llu",
                 (unsigned long long)config->data_mount_points_updated_at);
        send_all(fd, "<h2>Mesh mount points</h2><ul>");
        for (int i = 0; i < config->data_mount_point_count; i++) {
            send_all(fd, "<li>");
            send_all(fd, config->data_mount_points[i]);
            send_all(fd, "</li>");
        }
        send_all(fd, "</ul><p>Updated at: ");
        send_all(fd, stamp);
        send_all(fd, "</p>");
    }

    send_all(fd, "<h2>Directory listing</h2><ul>");
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        send_all(fd, "<li>");
        if (ent->d_type == DT_DIR) {
            send_all(fd, "<strong>");
            send_all(fd, ent->d_name);
            send_all(fd, "/</strong>");
            send_all(fd, " (<a href=\"/browse/");
            if (rel_path && rel_path[0] != '\0') {
                send_all(fd, rel_path);
                send_all(fd, "/");
            }
            send_all(fd, ent->d_name);
            send_all(fd, "\">browse</a>)");
        } else {
            send_all(fd, "<a href=\"/files/");
            if (rel_path && rel_path[0] != '\0') {
                send_all(fd, rel_path);
                send_all(fd, "/");
            }
            send_all(fd, ent->d_name);
            send_all(fd, "\">");
            send_all(fd, ent->d_name);
            send_all(fd, "</a>");
        }
        send_all(fd, "</li>");
    }
    closedir(dir);
    send_all(fd, "</ul>");
    send_html_footer(fd);
}

static void respond_file(int fd, const char *path) {
    int in = open(path, O_RDONLY);
    if (in < 0) {
        send_status(fd, 404, "Not Found");
        return;
    }

    struct stat st;
    if (fstat(in, &st) != 0) {
        close(in);
        send_status(fd, 500, "Error");
        return;
    }

    char header[256];
    snprintf(header, sizeof(header),
             "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
             (size_t)st.st_size);
    send_all(fd, header);

    char buf[4096];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        send(fd, buf, (size_t)n, 0);
    }
    close(in);
}

static int find_chunk_path(junknas_config_t *config, const char *hash, char *out, size_t out_len) {
    size_t dir_count = (config->data_dir_count > 0) ? config->data_dir_count : 1;
    for (size_t i = 0; i < dir_count && i < MAX_DATA_DIRS; i++) {
        const char *dir = (config->data_dir_count > 0) ? config->data_dirs[i] : config->data_dir;
        if (chunk_path_for_hash(dir, hash, out, out_len) == 0) {
            if (access(out, R_OK) == 0) return 0;
        }
    }
    return -1;
}

static void ensure_parent_dir(const char *path) {
    char tmp[MAX_PATH_LEN];
    snprintf(tmp, sizeof(tmp), "%s", path);
    char *slash = strrchr(tmp, '/');
    if (!slash) return;
    *slash = '\0';
    mkdir(tmp, 0755);
}

static void handle_get(web_conn_t *conn, const char *path) {
    if (strcmp(path, "/") == 0) {
        respond_mount_listing(conn->fd, conn->config, "");
        return;
    }

    if (strncmp(path, "/browse/", 8) == 0) {
        const char *rel = path + 8;
        if (!is_safe_relative(rel)) {
            send_status(conn->fd, 400, "Bad Request");
            return;
        }
        respond_mount_listing(conn->fd, conn->config, rel);
        return;
    }

    if (strncmp(path, "/files/", 7) == 0) {
        const char *rel = path + 7;
        if (!is_safe_relative(rel)) {
            send_status(conn->fd, 400, "Bad Request");
            return;
        }
        char full_path[MAX_PATH_LEN];
        snprintf(full_path, sizeof(full_path), "%s/%s", conn->config->mount_point, rel);
        respond_file(conn->fd, full_path);
        return;
    }

    if (strncmp(path, "/chunks/", 8) == 0) {
        const char *hash = path + 8;
        if (!is_hex64(hash)) {
            send_status(conn->fd, 400, "Bad Request");
            return;
        }
        char chunk_path[MAX_PATH_LEN];
        if (find_chunk_path(conn->config, hash, chunk_path, sizeof(chunk_path)) != 0) {
            send_status(conn->fd, 404, "Not Found");
            return;
        }
        respond_file(conn->fd, chunk_path);
        return;
    }

    if (strcmp(path, "/mesh/peers") == 0) {
        respond_mesh_state(conn->fd, conn->config);
        return;
    }

    if (strcmp(path, "/mesh/config") == 0) {
        respond_mesh_config(conn->fd, conn->config);
        return;
    }

    if (strcmp(path, "/mesh/status") == 0) {
        respond_mesh_status(conn->fd, conn->config);
        return;
    }

    if (strcmp(path, "/mesh/ui") == 0 || strcmp(path, "/mesh") == 0) {
        respond_mesh_ui(conn->fd);
        return;
    }

    send_status(conn->fd, 404, "Not Found");
}

static int read_headers(int fd, char *buf, size_t buf_len, size_t *out_len) {
    size_t used = 0;
    while (used + 1 < buf_len) {
        ssize_t n = recv(fd, buf + used, buf_len - used - 1, 0);
        if (n <= 0) break;
        used += (size_t)n;
        buf[used] = '\0';
        if (strstr(buf, "\r\n\r\n")) {
            if (out_len) *out_len = used;
            return 0;
        }
    }
    return -1;
}

static const char *find_header_case_insensitive(const char *headers, const char *needle) {
    if (!headers || !needle) return NULL;
    size_t nlen = strlen(needle);
    for (const char *p = headers; *p != '\0'; p++) {
        size_t i = 0;
        while (i < nlen && p[i] != '\0' &&
               tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == nlen) return p;
    }
    return NULL;
}

static long parse_content_length(const char *headers) {
    const char *cl = find_header_case_insensitive(headers, "Content-Length:");
    if (!cl) return -1;
    cl += strlen("Content-Length:");
    while (*cl == ' ' || *cl == '\t') cl++;
    char *end = NULL;
    long val = strtol(cl, &end, 10);
    if (end == cl || val < 0) return -1;
    return val;
}

static void handle_post_chunk(web_conn_t *conn, const char *hash, const char *headers, const char *body, size_t body_len) {
    if (!is_hex64(hash)) {
        send_status(conn->fd, 400, "Bad Request");
        return;
    }

    long content_len = parse_content_length(headers);
    if (content_len < 0) {
        send_status(conn->fd, 411, "Length Required");
        return;
    }

    char chunk_path[MAX_PATH_LEN];
    const char *dir = (conn->config->data_dir_count > 0) ? conn->config->data_dirs[0] : conn->config->data_dir;
    if (chunk_path_for_hash(dir, hash, chunk_path, sizeof(chunk_path)) != 0) {
        send_status(conn->fd, 400, "Bad Request");
        return;
    }
    ensure_parent_dir(chunk_path);

    int out = open(chunk_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) {
        send_status(conn->fd, 500, "Error");
        return;
    }

    if (body_len > 0) {
        write(out, body, body_len);
    }
    size_t remaining = (size_t)content_len > body_len ? (size_t)content_len - body_len : 0;
    char buf[4096];
    while (remaining > 0) {
        ssize_t n = recv(conn->fd, buf, remaining > sizeof(buf) ? sizeof(buf) : remaining, 0);
        if (n <= 0) break;
        write(out, buf, (size_t)n);
        remaining -= (size_t)n;
    }
    close(out);

    send_text(conn->fd, 200, "OK\n");
}

static void handle_connection(web_conn_t *conn) {
    char buf[WEB_BUF_SIZE];
    size_t header_len = 0;
    if (read_headers(conn->fd, buf, sizeof(buf), &header_len) != 0) {
        send_status(conn->fd, 400, "Bad Request");
        return;
    }

    char *header_end = strstr(buf, "\r\n\r\n");
    if (!header_end) {
        send_status(conn->fd, 400, "Bad Request");
        return;
    }
    size_t body_len = header_len - (size_t)(header_end + 4 - buf);
    const char *body = header_end + 4;

    char method[8];
    char path[512];
    if (sscanf(buf, "%7s %511s", method, path) != 2) {
        send_status(conn->fd, 400, "Bad Request");
        return;
    }

    if (strcmp(method, "GET") == 0) {
        handle_get(conn, path);
        return;
    }

    if (strcmp(method, "POST") == 0) {
        if (strcmp(path, "/mesh/peers") == 0) {
            int updated = merge_mesh_payload(conn->config, body);
            if (updated >= 0) {
                respond_mesh_state(conn->fd, conn->config);
            } else {
                send_status(conn->fd, 400, "Bad Request");
            }
            return;
        }
        if (strcmp(path, "/mesh/bootstrap") == 0) {
            (void)respond_mesh_bootstrap(conn->fd, conn->config);
            return;
        }
        if (strcmp(path, "/mesh/join") == 0) {
            (void)respond_mesh_join(conn->fd, conn->config, body);
            return;
        }
        if (strcmp(path, "/mesh/alternate") == 0) {
            (void)respond_mesh_alternate(conn->fd, conn->config, body);
            return;
        }
        if (strcmp(path, "/mesh/config") == 0) {
            if (update_mesh_config(conn->config, body) == 0) {
                respond_mesh_config(conn->fd, conn->config);
            } else {
                send_status(conn->fd, 400, "Bad Request");
            }
            return;
        }
        if (strcmp(path, "/mesh/sync") == 0) {
            cJSON *payload_json = build_mesh_state_json(conn->config);
            if (!payload_json) {
                send_status(conn->fd, 500, "Error");
                return;
            }
            char *payload = cJSON_PrintUnformatted(payload_json);
            cJSON_Delete(payload_json);
            if (!payload) {
                send_status(conn->fd, 500, "Error");
                return;
            }

            junknas_config_lock(conn->config);
            int bootstrap_count = conn->config->bootstrap_peer_count;
            char bootstrap[MAX_BOOTSTRAP_PEERS][MAX_ENDPOINT_LEN];
            for (int i = 0; i < bootstrap_count; i++) {
                snprintf(bootstrap[i], sizeof(bootstrap[i]), "%s", conn->config->bootstrap_peers[i]);
            }
            int wg_count = conn->config->wg_peer_count;
            junknas_wg_peer_t wg_peers[MAX_WG_PEERS];
            if (wg_count > MAX_WG_PEERS) wg_count = MAX_WG_PEERS;
            for (int i = 0; i < wg_count; i++) {
                wg_peers[i] = conn->config->wg_peers[i];
            }
            uint16_t default_web_port = conn->config->web_port;
            junknas_config_unlock(conn->config);

            int synced = 0;
            for (int i = 0; i < bootstrap_count; i++) {
                int rc = sync_mesh_with_peer(conn->config, bootstrap[i], payload);
                junknas_config_lock(conn->config);
                conn->config->bootstrap_peer_status[i] = (rc == 0) ? 1 : 0;
                junknas_config_unlock(conn->config);
                if (rc == 0) synced++;
            }

            for (int i = 0; i < wg_count; i++) {
                uint16_t web_port = wg_peers[i].web_port ? wg_peers[i].web_port : default_web_port;
                char endpoint[MAX_ENDPOINT_LEN];
                snprintf(endpoint, sizeof(endpoint), "%s:%u", wg_peers[i].wg_ip, web_port);
                int rc = sync_mesh_with_peer(conn->config, endpoint, payload);
                junknas_config_lock(conn->config);
                conn->config->wg_peer_status[i] = (rc == 0) ? 1 : 0;
                junknas_config_unlock(conn->config);
                if (rc == 0) synced++;
            }

            free(payload);
            char response[128];
            snprintf(response, sizeof(response), "{\"synced\":%d}", synced);
            send_json(conn->fd, 200, response);
            return;
        }
        if (strncmp(path, "/chunks/", 8) == 0) {
            handle_post_chunk(conn, path + 8, buf, body, body_len);
            return;
        }
        send_status(conn->fd, 404, "Not Found");
        return;
    }

    send_status(conn->fd, 405, "Method Not Allowed");
}

static void *connection_thread(void *arg) {
    web_conn_t *conn = (web_conn_t *)arg;
    handle_connection(conn);
    close(conn->fd);
    free(conn);
    return NULL;
}

static void *server_thread(void *arg) {
    struct junknas_web_server *server = (struct junknas_web_server *)arg;
    while (!server->stop) {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        int client = accept(server->fd, (struct sockaddr *)&addr, &addr_len);
        if (client < 0) {
            if (errno == EINTR) continue;
            break;
        }

        web_conn_t *conn = calloc(1, sizeof(*conn));
        if (!conn) {
            close(client);
            continue;
        }
        conn->fd = client;
        conn->config = server->config;

        pthread_t tid;
        if (pthread_create(&tid, NULL, connection_thread, conn) == 0) {
            pthread_detach(tid);
        } else {
            close(client);
            free(conn);
        }
    }
    return NULL;
}

junknas_web_server_t *junknas_web_server_start(junknas_config_t *config) {
    if (!config) return NULL;

    struct junknas_web_server *server = calloc(1, sizeof(*server));
    if (!server) {
        web_log_verbose(config, "web: failed to allocate server");
        return NULL;
    }

    server->config = config;
    server->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->fd < 0) {
        web_log_verbose(config, "web: failed to create socket");
        free(server);
        return NULL;
    }

    int opt = 1;
    setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(config->web_port);

    if (bind(server->fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        web_log_verbose(config, "web: bind failed on port %u", config->web_port);
        close(server->fd);
        free(server);
        return NULL;
    }

    if (listen(server->fd, WEB_BACKLOG) != 0) {
        web_log_verbose(config, "web: listen failed on port %u", config->web_port);
        close(server->fd);
        free(server);
        return NULL;
    }

    if (pthread_create(&server->thread, NULL, server_thread, server) != 0) {
        web_log_verbose(config, "web: failed to start web server thread");
        close(server->fd);
        free(server);
        return NULL;
    }

    web_log_verbose(config, "web: server listening on port %u", config->web_port);
    return server;
}

void junknas_web_server_stop(junknas_web_server_t *server) {
    if (!server) return;
    server->stop = 1;
    if (server->fd >= 0) close(server->fd);
    pthread_join(server->thread, NULL);
    free(server);
}
