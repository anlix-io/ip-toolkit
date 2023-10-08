"use strict";Object.defineProperty(exports, "__esModule", {value: true});var C=Object.defineProperty;var E=(t,r)=>{for(var n in r)C(t,n,{get:r[n],enumerable:!0})};var H=(t,r,n)=>{if(!r.has(t))throw TypeError("Cannot "+n)};var l=(t,r,n)=>(H(t,r,"read from private field"),n?n.call(t):r.get(t)),V=(t,r,n)=>{if(r.has(t))throw TypeError("Cannot add the same private member more than once");r instanceof WeakSet?r.add(t):r.set(t,n)},M=(t,r,n,e)=>(H(t,r,"write to private field"),e?e.call(t,n):r.set(t,n),n);var P={};E(P,{contains:()=>S,ip2long:()=>o,ipRange:()=>d,isConflict:()=>B,isEqual:()=>N,isPrivate:()=>$,isSameSubnet:()=>j,isValidIP:()=>i,isValidMask:()=>u,long2ip:()=>a,parseCIDR:()=>I,parseSubnet:()=>L,toBinHex:()=>G,toIPv6Format:()=>q,toInverseMask:()=>z,toMaskLength:()=>k,toSubnetMask:()=>h});function o(t){if(!i(t))return!1;let r=0,n=t.split(".");for(let e of n)r=(r<<8)+ +e;return r>>>0}function a(t){if(typeof t!="number")return!1;if(t>=0&&t<=4294967295){let r=[];for(let n=3;n>=0;n--)r.push(t>>>n*8&255);return r.join(".")}else return!1}var c,m,X=class X{constructor(r,n){V(this,c,void 0);V(this,m,void 0);if(+r<0||+r>4294967295||+n<0||+n>4294967295)throw new Error("Invalid start or end IPv4 address");M(this,c,r),M(this,m,n)}static fromLong(r,n){if(typeof r!="number"||typeof n!="number")throw new Error("Invalid start or end IPv4 address");if(+n<+r)throw new Error("Invalid range value, end must be greater than or equal to start");return new X(r,n)}static fromString(r,n){let e=o(r),s=o(n);if(typeof e!="number"||typeof s!="number")throw new Error("Invalid start or end IPv4 address");if(s<e)throw new Error("Invalid range value, end must be greater than or equal to start");return new X(e,s)}ip2long(){return[l(this,c),l(this,m)]}long2ip(){return[a(l(this,c)),a(l(this,m))]}ipCount(){return l(this,m)-l(this,c)+1}contains(r){let n=o(r);return typeof n!="number"?!1:n>=l(this,c)&&n<=l(this,m)}};c=new WeakMap,m=new WeakMap;var d=X;function N(t,r){return typeof t=="number"&&(t<0||t>4294967295)||typeof r=="number"&&(r<0||r>4294967295)||(typeof t=="string"&&(t=o(t)),typeof r=="string"&&(r=o(r)),typeof t!="number"||typeof r!="number")?!1:t===r}function S(t,r){let n=I(t);if(typeof n!="object"||!i(r))return!1;let{cidrMask:e,firstHost:s,lastHost:f,networkAddress:p,broadcastAddress:x}=n;return e>=31?d.fromString(s,f).contains(r):d.fromString(p,x).contains(r)}function i(t,r={strict:!1}){return r.strict?/^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])(\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)){3}$/.test(t):/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$/.test(t)}function $(t){if(!i(t))return!1;let r=[{start:"10.0.0.0",end:"10.255.255.255"},{start:"127.0.0.0",end:"127.255.255.255"},{start:"172.16.0.0",end:"172.31.255.255"},{start:"169.254.0.0",end:"169.254.255.255"},{start:"192.168.0.0",end:"192.168.255.255"}];for(let n of r)if(d.fromString(n.start,n.end).contains(t))return!0;return!1}function I(t){if(typeof t!="string")return!1;let[r,n]=t.split("/");if(!i(r)||!u(+n))return!1;let e=32-+n,s=o(r),f=Number(0b1n<<BigInt(e)),p=+n?s>>e<<e>>>0:0,x=(p|f-1)>>>0;return{ipCount:f,cidrMask:+n,usableCount:+n<31?f-2:f,subnetMask:h(+n),networkAddress:+n<31?a(p):"",broadcastAddress:+n<31?a(x):"",firstHost:a(p+(+n<31?1:0)),lastHost:a(x-(+n<31?1:0))}}function B(t){if(!Array.isArray(t)||t.length===0)return!1;let r=[];for(let n of t){let e=I(n);typeof e=="object"&&r.push({cidr:n,networkAddress:e.networkAddress||e.firstHost})}for(let n=0;n<r.length;n++)for(let e=n+1;e<r.length;e++){let s=S(r[e].cidr,r[n].networkAddress),f=S(r[n].cidr,r[e].networkAddress);if(s||f)return!0}return!1}function L(t,r){if(!i(t)||!u(r))return!1;let n=k(r);return I(`${t}/${n}`)}function u(t){if(typeof t=="number"&&!isNaN(t))return!(t<0||t>32);if(typeof t=="string"){let r=o(t);return typeof r!="number"?!1:/^1*0*$/.test(r.toString(2).padStart(32,"0"))}else return!1}function j(t,r,n){if(!i(t)||!i(r)||!u(n))return!1;let e=o(t),s=o(r);typeof n=="number"&&(n=h(n));let f=o(n);return(e&f)===(s&f)}function G(t){if(!i(t))return!1;let r=o(t);return{decimal:r,hex:`0x${r.toString(16).padStart(8,"0")}`,binary:r.toString(2).padStart(32,"0")}}var R={};E(R,{compressedForm:()=>y,expandedForm:()=>A,ip2long:()=>b,isEqual:()=>_,isValidIP:()=>g,long2ip:()=>F,parseCIDR:()=>D});function b(t){if(!g(t))return!1;let r=[];t=A(t);let n=t.split(":");for(let e=0;e<n.length;e++){let s=parseInt(n[e],16);r.push(s.toString(2).padStart(16,"0"))}return BigInt(`0b${r.join("")}`)}function y(t){if(!g(t))return!1;if(b(t)===0n)return"::";t=A(t);let n=t.split(":").map(s=>{let f=parseInt(s,16);return f?f.toString(16):"X"}).join(":"),e=[/(X:X:X:X:X:X:X)/,/(X:X:X:X:X:X)/,/(X:X:X:X:X)/,/(X:X:X:X)/,/(X:X:X)/,/(X:X)/];for(let s=0;s<e.length;s++)if(n.match(e[s]))return n.replace(e[s],":").replace(":::","::").replaceAll("X","0");return n.replaceAll("X","0")}function F(t){if(typeof t!="bigint")return!1;if(t>=0n&&t<=340282366920938463463374607431768211455n){let r=[],n=t.toString(16).padStart(32,"0");for(let e=0;e<8;e++)r.push(n.slice(e*4,(e+1)*4));return y(r.join(":"))}else return!1}function _(t,r){return typeof t=="bigint"&&(t<0n||t>340282366920938463463374607431768211455n)||typeof r=="bigint"&&(r<0||r>340282366920938463463374607431768211455n)||(typeof t=="string"&&(t=b(t)),typeof r=="string"&&(r=b(r)),typeof t!="bigint"||typeof r!="bigint")?!1:t===r}function g(t){return/^[\s]*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}))|:)))(%.+)?[\s]*$/.test(t)}function D(t){if(typeof t!="string")return!1;let[r,n]=t.split("/");if(r===void 0||n===void 0)return!1;let e=+n;if(!g(r)||isNaN(e)||e<0||e>128)return!1;let s=BigInt(128-e),f=b(r),p=BigInt(0b1n<<s),x=f>>s<<s,w=F(x),v=F(x|p-1n);return{ipCount:p,firstHost:w,lastHost:v,prefixLength:e}}function A(t){if(!g(t))return!1;if(t==="::")return"0000:".repeat(8).slice(0,-1);let r=t.split(":");for(let e=0;e<r.length;e++)r[e]===""&&r[e+1]===""&&r.splice(e,1);let n=r[r.length-1];if(P.isValidIP(n)){let e=P.toBinHex(n).hex.slice(2);r.pop()&&r.push(e.slice(0,4),e.slice(4))}return r.map(e=>e?e.padStart(4,"0"):"0000:".repeat(9-r.length).slice(0,-1)).join(":")}function q(t){if(!i(t))return!1;let r=o(t),n=a(r);return{mapped:`::ffff:${n}`,comperssed:y(`::ffff:${n}`),expanded:A(`::ffff:${n}`)}}function h(t){if(typeof t!="number"||isNaN(t)||!u(t))return!1;let r=4294967295<<32-t;return t?a(r>>>0):"0.0.0.0"}function k(t){if(typeof t!="string"||!u(t))return!1;let r=o(t);return r===0?0:r.toString(2).replaceAll("0","").length}function z(t){if(!u(t))return!1;typeof t=="number"&&(t=h(t));let n=~o(t)>>>0;return a(n)}exports.IPv4 = P; exports.IPv6 = R;
