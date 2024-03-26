var L=Object.defineProperty;var H=(t,r)=>{for(var n in r)L(t,n,{get:r[n],enumerable:!0})};var E=(t,r,n)=>{if(!r.has(t))throw TypeError("Cannot "+n)};var b=(t,r,n)=>(E(t,r,"read from private field"),n?n.call(t):r.get(t)),M=(t,r,n)=>{if(r.has(t))throw TypeError("Cannot add the same private member more than once");r instanceof WeakSet?r.add(t):r.set(t,n)},k=(t,r,n,e)=>(E(t,r,"write to private field"),e?e.call(t,n):r.set(t,n),n);var D={};H(D,{contains:()=>q,ip2long:()=>$,isCIDR:()=>_,isConflict:()=>G,isValidIP:()=>N,long2ip:()=>B});function $(t){return N(t)?l.ip2long(t)||d.ip2long(t):!1}function B(t){return typeof t!="number"&&typeof t!="bigint"?!1:l.long2ip(t)||d.long2ip(t)}function _(t){return typeof t!="string"?!1:l.isCIDR(t)||d.isCIDR(t)}function N(t){return typeof t!="string"?!1:l.isValidIP(t)||d.isValidIP(t)}function G(t){return!Array.isArray(t)||t.length===0?!1:l.isConflict(t)||d.isConflict(t)}function q(t,r){return typeof t!="string"||typeof r!="string"?!1:l.contains(t,r)||d.contains(t,r)}var l={};H(l,{contains:()=>S,ip2long:()=>s,ipRange:()=>h,isCIDR:()=>z,isConflict:()=>O,isEqual:()=>J,isPrivate:()=>K,isSameSubnet:()=>T,isValidIP:()=>f,isValidMask:()=>u,long2ip:()=>a,parseCIDR:()=>x,parseSubnet:()=>Q,toBinHex:()=>U,toIPv6Format:()=>tt,toInverseMask:()=>rt,toMaskLength:()=>w,toSubnetMask:()=>P});function s(t){if(!f(t))return!1;let r=0,n=t.split(".");for(let e of n)r=(r<<8)+ +e;return r>>>0}function a(t){if(typeof t!="number"||isNaN(t))return!1;if(t>=0&&t<=4294967295){let r=[];for(let n=3;n>=0;n--)r.push(t>>>n*8&255);return r.join(".")}else return!1}var I,y,R=class R{constructor(r,n){M(this,I,void 0);M(this,y,void 0);if(+r<0||+r>4294967295||+n<0||+n>4294967295)throw new Error("Invalid start or end IPv4 address");k(this,I,r),k(this,y,n)}static fromLong(r,n){if(typeof r!="number"||typeof n!="number")throw new Error("Invalid start or end IPv4 address");if(+n<+r)throw new Error("Invalid range value, end must be greater than or equal to start");return new R(r,n)}static fromString(r,n){let e=s(r),o=s(n);if(typeof e!="number"||typeof o!="number")throw new Error("Invalid start or end IPv4 address");if(o<e)throw new Error("Invalid range value, end must be greater than or equal to start");return new R(e,o)}ip2long(){return[b(this,I),b(this,y)]}long2ip(){return[a(b(this,I)),a(b(this,y))]}ipCount(){return b(this,y)-b(this,I)+1}contains(r){let n=s(r);return typeof n!="number"?!1:n>=b(this,I)&&n<=b(this,y)}};I=new WeakMap,y=new WeakMap;var h=R;function z(t){return typeof t!="string"?!1:typeof x(t)=="object"}function J(t,r){return typeof t=="number"&&(t<0||t>4294967295)||typeof r=="number"&&(r<0||r>4294967295)||(typeof t=="string"&&(t=s(t)),typeof r=="string"&&(r=s(r)),typeof t!="number"||typeof r!="number")?!1:t===r}function S(t,r){let n=x(t);if(typeof n!="object"||!f(r))return!1;let{cidrMask:e,firstHost:o,lastHost:i,networkAddress:c,broadcastAddress:m}=n;return e>=31?h.fromString(o,i).contains(r):h.fromString(c,m).contains(r)}function f(t,r={strict:!1}){return r.strict?/^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])(\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)){3}$/.test(t):/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$/.test(t)}function K(t){if(!f(t))return!1;let r=[{start:"10.0.0.0",end:"10.255.255.255"},{start:"127.0.0.0",end:"127.255.255.255"},{start:"172.16.0.0",end:"172.31.255.255"},{start:"169.254.0.0",end:"169.254.255.255"},{start:"192.168.0.0",end:"192.168.255.255"}];for(let n of r)if(h.fromString(n.start,n.end).contains(t))return!0;return!1}function x(t){if(typeof t!="string")return!1;let[r,n]=t.split("/");if(r===void 0||n===void 0||n===""||!f(r)||!u(+n))return!1;let e=32-+n,o=s(r),i=Number(0b1n<<BigInt(e)),c=+n?o>>e<<e>>>0:0,m=(c|i-1)>>>0;return{ipCount:i,cidrMask:+n,usableCount:+n<31?i-2:i,subnetMask:P(+n),networkAddress:+n<31?a(c):"",broadcastAddress:+n<31?a(m):"",firstHost:a(c+(+n<31?1:0)),lastHost:a(m-(+n<31?1:0))}}function O(t){if(!Array.isArray(t)||t.length===0)return!1;let r=[];for(let n of t){let e=x(n);typeof e=="object"&&r.push({cidr:n,networkAddress:e.networkAddress||e.firstHost})}for(let n=0;n<r.length;n++)for(let e=n+1;e<r.length;e++){let o=S(r[e].cidr,r[n].networkAddress),i=S(r[n].cidr,r[e].networkAddress);if(o||i)return!0}return!1}function Q(t,r){if(!f(t)||!u(r))return!1;let n=w(r);return x(`${t}/${n}`)}function u(t){if(typeof t=="number"&&!isNaN(t))return!(t<0||t>32);if(typeof t=="string"){let r=s(t);return typeof r!="number"?!1:/^1*0*$/.test(r.toString(2).padStart(32,"0"))}else return!1}function T(t,r,n){if(!f(t)||!f(r)||!u(n))return!1;let e=s(t),o=s(r);typeof n=="number"&&(n=P(n));let i=s(n);return(e&i)===(o&i)}function U(t){if(!f(t))return!1;let r=s(t);return{decimal:r,hex:`0x${r.toString(16).padStart(8,"0")}`,binary:r.toString(2).padStart(32,"0")}}var d={};H(d,{compressedForm:()=>V,contains:()=>F,expandedForm:()=>A,ip2long:()=>g,isCIDR:()=>W,isConflict:()=>Z,isEqual:()=>Y,isValidIP:()=>p,long2ip:()=>C,parseCIDR:()=>X});function g(t){if(!p(t))return!1;let r=[];t=A(t);let n=t.split(":");for(let e=0;e<n.length;e++){let o=parseInt(n[e],16);r.push(o.toString(2).padStart(16,"0"))}return BigInt(`0b${r.join("")}`)}function V(t){if(!p(t))return!1;if(g(t)===0n)return"::";t=A(t);let n=t.split(":").map(o=>{let i=parseInt(o,16);return i?i.toString(16):"X"}).join(":"),e=[/(X:X:X:X:X:X:X)/,/(X:X:X:X:X:X)/,/(X:X:X:X:X)/,/(X:X:X:X)/,/(X:X:X)/,/(X:X)/];for(let o=0;o<e.length;o++)if(n.match(e[o]))return n.replace(e[o],":").replace(":::","::").replaceAll("X","0");return n.replaceAll("X","0")}function C(t){if(typeof t!="bigint")return!1;if(t>=0n&&t<=340282366920938463463374607431768211455n){let r=[],n=t.toString(16).padStart(32,"0");for(let e=0;e<8;e++)r.push(n.slice(e*4,(e+1)*4));return V(r.join(":"))}else return!1}function F(t,r){let n=X(t);if(typeof n!="object"||!p(r))return!1;let{lastHost:e,firstHost:o}=n,i=g(r),c=g(e),m=g(o);return i>=m&&i<=c}function W(t){return typeof t!="string"?!1:typeof X(t)=="object"}function Y(t,r){return typeof t=="bigint"&&(t<0n||t>340282366920938463463374607431768211455n)||typeof r=="bigint"&&(r<0||r>340282366920938463463374607431768211455n)||(typeof t=="string"&&(t=g(t)),typeof r=="string"&&(r=g(r)),typeof t!="bigint"||typeof r!="bigint")?!1:t===r}function p(t){return/^[\s]*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}))|:)))(%.+)?[\s]*$/.test(t)}function Z(t){if(!Array.isArray(t)||t.length===0)return!1;let r=[];for(let n of t){let e=X(n);typeof e=="object"&&r.push({cidr:n,firstHost:e.firstHost})}for(let n=0;n<r.length;n++)for(let e=n+1;e<r.length;e++){let o=F(r[e].cidr,r[n].firstHost),i=F(r[n].cidr,r[e].firstHost);if(o||i)return!0}return!1}function X(t){if(typeof t!="string")return!1;let[r,n]=t.split("/");if(r===void 0||n===void 0||n==="")return!1;let e=+n;if(!p(r)||isNaN(e)||e<0||e>128)return!1;let o=BigInt(128-e),i=g(r),c=BigInt(0b1n<<o),m=i>>o<<o,v=C(m),j=C(m|c-1n);return{ipCount:c,firstHost:v,lastHost:j,prefixLength:e}}function A(t){if(!p(t))return!1;if(t==="::")return"0000:".repeat(8).slice(0,-1);let r=t.split(":");for(let e=0;e<r.length;e++)r[e]===""&&r[e+1]===""&&r.splice(e,1);let n=r[r.length-1];if(l.isValidIP(n)){let e=l.toBinHex(n).hex.slice(2);r.pop()&&r.push(e.slice(0,4),e.slice(4))}return r.map(e=>e?e.padStart(4,"0"):"0000:".repeat(9-r.length).slice(0,-1)).join(":")}function tt(t){if(!f(t))return!1;let r=s(t),n=a(r);return{mapped:`::ffff:${n}`,comperssed:V(`::ffff:${n}`),expanded:A(`::ffff:${n}`)}}function P(t){if(typeof t!="number"||isNaN(t)||!u(t))return!1;let r=4294967295<<32-t;return t?a(r>>>0):"0.0.0.0"}function w(t){if(typeof t!="string"||!u(t))return!1;let r=s(t);return r===0?0:r.toString(2).replaceAll("0","").length}function rt(t){if(!u(t))return!1;typeof t=="number"&&(t=P(t));let n=~s(t)>>>0;return a(n)}export{D as IP,l as IPv4,d as IPv6};
