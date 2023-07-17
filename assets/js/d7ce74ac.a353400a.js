"use strict";(self.webpackChunkstacklok=self.webpackChunkstacklok||[]).push([[6504],{3905:(e,r,n)=>{n.d(r,{Zo:()=>d,kt:()=>f});var t=n(7294);function o(e,r,n){return r in e?Object.defineProperty(e,r,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[r]=n,e}function i(e,r){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var t=Object.getOwnPropertySymbols(e);r&&(t=t.filter((function(r){return Object.getOwnPropertyDescriptor(e,r).enumerable}))),n.push.apply(n,t)}return n}function l(e){for(var r=1;r<arguments.length;r++){var n=null!=arguments[r]?arguments[r]:{};r%2?i(Object(n),!0).forEach((function(r){o(e,r,n[r])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):i(Object(n)).forEach((function(r){Object.defineProperty(e,r,Object.getOwnPropertyDescriptor(n,r))}))}return e}function a(e,r){if(null==e)return{};var n,t,o=function(e,r){if(null==e)return{};var n,t,o={},i=Object.keys(e);for(t=0;t<i.length;t++)n=i[t],r.indexOf(n)>=0||(o[n]=e[n]);return o}(e,r);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(t=0;t<i.length;t++)n=i[t],r.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(o[n]=e[n])}return o}var c=t.createContext({}),p=function(e){var r=t.useContext(c),n=r;return e&&(n="function"==typeof e?e(r):l(l({},r),e)),n},d=function(e){var r=p(e.components);return t.createElement(c.Provider,{value:r},e.children)},s="mdxType",m={inlineCode:"code",wrapper:function(e){var r=e.children;return t.createElement(t.Fragment,{},r)}},u=t.forwardRef((function(e,r){var n=e.components,o=e.mdxType,i=e.originalType,c=e.parentName,d=a(e,["components","mdxType","originalType","parentName"]),s=p(n),u=o,f=s["".concat(c,".").concat(u)]||s[u]||m[u]||i;return n?t.createElement(f,l(l({ref:r},d),{},{components:n})):t.createElement(f,l({ref:r},d))}));function f(e,r){var n=arguments,o=r&&r.mdxType;if("string"==typeof e||o){var i=n.length,l=new Array(i);l[0]=u;var a={};for(var c in r)hasOwnProperty.call(r,c)&&(a[c]=r[c]);a.originalType=e,a[s]="string"==typeof e?e:o,l[1]=a;for(var p=2;p<i;p++)l[p]=n[p];return t.createElement.apply(null,l)}return t.createElement.apply(null,n)}u.displayName="MDXCreateElement"},5558:(e,r,n)=>{n.r(r),n.d(r,{assets:()=>c,contentTitle:()=>l,default:()=>m,frontMatter:()=>i,metadata:()=>a,toc:()=>p});var t=n(7462),o=(n(7294),n(3905));const i={},l=void 0,a={unversionedId:"cli/medic_enroll_provider",id:"cli/medic_enroll_provider",title:"medic_enroll_provider",description:"medic enroll provider",source:"@site/docs/cli/medic_enroll_provider.md",sourceDirName:"cli",slug:"/cli/medic_enroll_provider",permalink:"/cli/medic_enroll_provider",draft:!1,tags:[],version:"current",frontMatter:{},sidebar:"mediator",previous:{title:"medic_enroll",permalink:"/cli/medic_enroll"},next:{title:"medic_group",permalink:"/cli/medic_group"}},c={},p=[{value:"medic enroll provider",id:"medic-enroll-provider",level:2},{value:"Synopsis",id:"synopsis",level:3},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],d={toc:p},s="wrapper";function m(e){let{components:r,...n}=e;return(0,o.kt)(s,(0,t.Z)({},d,n,{components:r,mdxType:"MDXLayout"}),(0,o.kt)("h2",{id:"medic-enroll-provider"},"medic enroll provider"),(0,o.kt)("p",null,"Enroll a provider within the mediator control plane"),(0,o.kt)("h3",{id:"synopsis"},"Synopsis"),(0,o.kt)("p",null,"The medic enroll provider command allows a user to enroll a provider\nsuch as GitHub into the mediator control plane. Once enrolled, users can perform\nactions such as adding repositories."),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},"medic enroll provider [flags]\n")),(0,o.kt)("h3",{id:"options"},"Options"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},"  -g, --group-id int32    ID of the group for enrolling the provider\n  -h, --help              help for provider\n  -n, --provider string   Name for the provider to enroll\n  -t, --token string      Personal Access Token (PAT) to use for enrollment\n")),(0,o.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},'      --config string      config file (default is $PWD/config.yaml)\n      --grpc-host string   Server host (default "localhost")\n      --grpc-port int      Server port (default 8090)\n')),(0,o.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,o.kt)("ul",null,(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"/cli/medic_enroll"},"medic enroll"),"\t - Manage enrollments within a mediator control plane")))}m.isMDXComponent=!0}}]);