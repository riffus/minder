"use strict";(self.webpackChunkstacklok=self.webpackChunkstacklok||[]).push([[3160],{3905:(e,r,t)=>{t.d(r,{Zo:()=>s,kt:()=>u});var n=t(67294);function i(e,r,t){return r in e?Object.defineProperty(e,r,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[r]=t,e}function o(e,r){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);r&&(n=n.filter((function(r){return Object.getOwnPropertyDescriptor(e,r).enumerable}))),t.push.apply(t,n)}return t}function l(e){for(var r=1;r<arguments.length;r++){var t=null!=arguments[r]?arguments[r]:{};r%2?o(Object(t),!0).forEach((function(r){i(e,r,t[r])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):o(Object(t)).forEach((function(r){Object.defineProperty(e,r,Object.getOwnPropertyDescriptor(t,r))}))}return e}function a(e,r){if(null==e)return{};var t,n,i=function(e,r){if(null==e)return{};var t,n,i={},o=Object.keys(e);for(n=0;n<o.length;n++)t=o[n],r.indexOf(t)>=0||(i[t]=e[t]);return i}(e,r);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(n=0;n<o.length;n++)t=o[n],r.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(i[t]=e[t])}return i}var c=n.createContext({}),p=function(e){var r=n.useContext(c),t=r;return e&&(t="function"==typeof e?e(r):l(l({},r),e)),t},s=function(e){var r=p(e.components);return n.createElement(c.Provider,{value:r},e.children)},f="mdxType",d={inlineCode:"code",wrapper:function(e){var r=e.children;return n.createElement(n.Fragment,{},r)}},m=n.forwardRef((function(e,r){var t=e.components,i=e.mdxType,o=e.originalType,c=e.parentName,s=a(e,["components","mdxType","originalType","parentName"]),f=p(t),m=i,u=f["".concat(c,".").concat(m)]||f[m]||d[m]||o;return t?n.createElement(u,l(l({ref:r},s),{},{components:t})):n.createElement(u,l({ref:r},s))}));function u(e,r){var t=arguments,i=r&&r.mdxType;if("string"==typeof e||i){var o=t.length,l=new Array(o);l[0]=m;var a={};for(var c in r)hasOwnProperty.call(r,c)&&(a[c]=r[c]);a.originalType=e,a[f]="string"==typeof e?e:i,l[1]=a;for(var p=2;p<o;p++)l[p]=t[p];return n.createElement.apply(null,l)}return n.createElement.apply(null,t)}m.displayName="MDXCreateElement"},98261:(e,r,t)=>{t.r(r),t.d(r,{assets:()=>c,contentTitle:()=>l,default:()=>d,frontMatter:()=>o,metadata:()=>a,toc:()=>p});var n=t(87462),i=(t(67294),t(3905));const o={title:"minder profile create"},l=void 0,a={unversionedId:"ref/cli/minder_profile_create",id:"ref/cli/minder_profile_create",title:"minder profile create",description:"minder profile create",source:"@site/docs/ref/cli/minder_profile_create.md",sourceDirName:"ref/cli",slug:"/ref/cli/minder_profile_create",permalink:"/ref/cli/minder_profile_create",draft:!1,tags:[],version:"current",frontMatter:{title:"minder profile create"},sidebar:"mediator",previous:{title:"minder profile",permalink:"/ref/cli/minder_profile"},next:{title:"minder profile delete",permalink:"/ref/cli/minder_profile_delete"}},c={},p=[{value:"minder profile create",id:"minder-profile-create",level:2},{value:"Synopsis",id:"synopsis",level:3},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],s={toc:p},f="wrapper";function d(e){let{components:r,...t}=e;return(0,i.kt)(f,(0,n.Z)({},s,t,{components:r,mdxType:"MDXLayout"}),(0,i.kt)("h2",{id:"minder-profile-create"},"minder profile create"),(0,i.kt)("p",null,"Create a profile within a minder control plane"),(0,i.kt)("h3",{id:"synopsis"},"Synopsis"),(0,i.kt)("p",null,"The minder profile create subcommand lets you create new profiles for a project\nwithin a minder control plane."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"minder profile create [flags]\n")),(0,i.kt)("h3",{id:"options"},"Options"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"  -f, --file string      Path to the YAML defining the profile (or - for stdin)\n  -h, --help             help for create\n  -p, --project string   Project to create the profile in\n")),(0,i.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},'      --config string            Config file (default is $PWD/config.yaml)\n      --grpc-host string         Server host (default "staging.stacklok.dev")\n      --grpc-insecure            Allow establishing insecure connections\n      --grpc-port int            Server port (default 443)\n      --identity-client string   Identity server client ID (default "mediator-cli")\n      --identity-realm string    Identity server realm (default "stacklok")\n      --identity-url string      Identity server issuer URL (default "https://auth.staging.stacklok.dev")\n')),(0,i.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/ref/cli/minder_profile"},"minder profile"),"\t - Manage profiles within a minder control plane")))}d.isMDXComponent=!0}}]);