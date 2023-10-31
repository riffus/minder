"use strict";(self.webpackChunkstacklok=self.webpackChunkstacklok||[]).push([[4172],{3905:(e,r,n)=>{n.d(r,{Zo:()=>s,kt:()=>f});var t=n(67294);function o(e,r,n){return r in e?Object.defineProperty(e,r,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[r]=n,e}function i(e,r){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var t=Object.getOwnPropertySymbols(e);r&&(t=t.filter((function(r){return Object.getOwnPropertyDescriptor(e,r).enumerable}))),n.push.apply(n,t)}return n}function l(e){for(var r=1;r<arguments.length;r++){var n=null!=arguments[r]?arguments[r]:{};r%2?i(Object(n),!0).forEach((function(r){o(e,r,n[r])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):i(Object(n)).forEach((function(r){Object.defineProperty(e,r,Object.getOwnPropertyDescriptor(n,r))}))}return e}function a(e,r){if(null==e)return{};var n,t,o=function(e,r){if(null==e)return{};var n,t,o={},i=Object.keys(e);for(t=0;t<i.length;t++)n=i[t],r.indexOf(n)>=0||(o[n]=e[n]);return o}(e,r);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(t=0;t<i.length;t++)n=i[t],r.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(o[n]=e[n])}return o}var p=t.createContext({}),d=function(e){var r=t.useContext(p),n=r;return e&&(n="function"==typeof e?e(r):l(l({},r),e)),n},s=function(e){var r=d(e.components);return t.createElement(p.Provider,{value:r},e.children)},c="mdxType",m={inlineCode:"code",wrapper:function(e){var r=e.children;return t.createElement(t.Fragment,{},r)}},u=t.forwardRef((function(e,r){var n=e.components,o=e.mdxType,i=e.originalType,p=e.parentName,s=a(e,["components","mdxType","originalType","parentName"]),c=d(n),u=o,f=c["".concat(p,".").concat(u)]||c[u]||m[u]||i;return n?t.createElement(f,l(l({ref:r},s),{},{components:n})):t.createElement(f,l({ref:r},s))}));function f(e,r){var n=arguments,o=r&&r.mdxType;if("string"==typeof e||o){var i=n.length,l=new Array(i);l[0]=u;var a={};for(var p in r)hasOwnProperty.call(r,p)&&(a[p]=r[p]);a.originalType=e,a[c]="string"==typeof e?e:o,l[1]=a;for(var d=2;d<i;d++)l[d]=n[d];return t.createElement.apply(null,l)}return t.createElement.apply(null,n)}u.displayName="MDXCreateElement"},60204:(e,r,n)=>{n.r(r),n.d(r,{assets:()=>p,contentTitle:()=>l,default:()=>m,frontMatter:()=>i,metadata:()=>a,toc:()=>d});var t=n(87462),o=(n(67294),n(3905));const i={title:"minder provider enroll"},l=void 0,a={unversionedId:"ref/cli/minder_provider_enroll",id:"ref/cli/minder_provider_enroll",title:"minder provider enroll",description:"minder provider enroll",source:"@site/docs/ref/cli/minder_provider_enroll.md",sourceDirName:"ref/cli",slug:"/ref/cli/minder_provider_enroll",permalink:"/ref/cli/minder_provider_enroll",draft:!1,tags:[],version:"current",frontMatter:{title:"minder provider enroll"},sidebar:"mediator",previous:{title:"minder provider",permalink:"/ref/cli/minder_provider"},next:{title:"minder repo",permalink:"/ref/cli/minder_repo"}},p={},d=[{value:"minder provider enroll",id:"minder-provider-enroll",level:2},{value:"Synopsis",id:"synopsis",level:3},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],s={toc:d},c="wrapper";function m(e){let{components:r,...n}=e;return(0,o.kt)(c,(0,t.Z)({},s,n,{components:r,mdxType:"MDXLayout"}),(0,o.kt)("h2",{id:"minder-provider-enroll"},"minder provider enroll"),(0,o.kt)("p",null,"Enroll a provider within the minder control plane"),(0,o.kt)("h3",{id:"synopsis"},"Synopsis"),(0,o.kt)("p",null,"The minder provider enroll command allows a user to enroll a provider\nsuch as GitHub into the minder control plane. Once enrolled, users can perform\nactions such as adding repositories."),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},"minder provider enroll [flags]\n")),(0,o.kt)("h3",{id:"options"},"Options"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},"  -h, --help                help for enroll\n  -o, --owner string        Owner to filter on for provider resources\n  -g, --project-id string   ID of the project for enrolling the provider\n  -n, --provider string     Name for the provider to enroll\n  -t, --token string        Personal Access Token (PAT) to use for enrollment\n")),(0,o.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},'      --config string            Config file (default is $PWD/config.yaml)\n      --grpc-host string         Server host (default "staging.stacklok.dev")\n      --grpc-insecure            Allow establishing insecure connections\n      --grpc-port int            Server port (default 443)\n      --identity-client string   Identity server client ID (default "mediator-cli")\n      --identity-realm string    Identity server realm (default "stacklok")\n      --identity-url string      Identity server issuer URL (default "https://auth.staging.stacklok.dev")\n')),(0,o.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,o.kt)("ul",null,(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"/ref/cli/minder_provider"},"minder provider"),"\t - Manage providers within a minder control plane")))}m.isMDXComponent=!0}}]);