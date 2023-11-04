"use strict";(self.webpackChunkstacklok=self.webpackChunkstacklok||[]).push([[4993],{3905:(e,t,r)=>{r.d(t,{Zo:()=>c,kt:()=>g});var n=r(67294);function o(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function i(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function l(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?i(Object(r),!0).forEach((function(t){o(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):i(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function a(e,t){if(null==e)return{};var r,n,o=function(e,t){if(null==e)return{};var r,n,o={},i=Object.keys(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||(o[r]=e[r]);return o}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(o[r]=e[r])}return o}var p=n.createContext({}),s=function(e){var t=n.useContext(p),r=t;return e&&(r="function"==typeof e?e(t):l(l({},t),e)),r},c=function(e){var t=s(e.components);return n.createElement(p.Provider,{value:t},e.children)},f="mdxType",u={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},d=n.forwardRef((function(e,t){var r=e.components,o=e.mdxType,i=e.originalType,p=e.parentName,c=a(e,["components","mdxType","originalType","parentName"]),f=s(r),d=o,g=f["".concat(p,".").concat(d)]||f[d]||u[d]||i;return r?n.createElement(g,l(l({ref:t},c),{},{components:r})):n.createElement(g,l({ref:t},c))}));function g(e,t){var r=arguments,o=t&&t.mdxType;if("string"==typeof e||o){var i=r.length,l=new Array(i);l[0]=d;var a={};for(var p in t)hasOwnProperty.call(t,p)&&(a[p]=t[p]);a.originalType=e,a[f]="string"==typeof e?e:o,l[1]=a;for(var s=2;s<i;s++)l[s]=r[s];return n.createElement.apply(null,l)}return n.createElement.apply(null,r)}d.displayName="MDXCreateElement"},35944:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>p,contentTitle:()=>l,default:()=>u,frontMatter:()=>i,metadata:()=>a,toc:()=>s});var n=r(87462),o=(r(67294),r(3905));const i={title:"Profile Introduction",sidebar_position:10},l="Profile Introduction",a={unversionedId:"profile_engine/profile_introduction",id:"profile_engine/profile_introduction",title:"Profile Introduction",description:"Minder allows you to define profiles for your software supply chain.",source:"@site/docs/profile_engine/profile_introduction.md",sourceDirName:"profile_engine",slug:"/profile_engine/profile_introduction",permalink:"/profile_engine/profile_introduction",draft:!1,tags:[],version:"current",sidebarPosition:10,frontMatter:{title:"Profile Introduction",sidebar_position:10},sidebar:"minder",previous:{title:"Register Repositories",permalink:"/getting_started/register_repos"},next:{title:"Manage profiles and violations",permalink:"/profile_engine/manage_profiles"}},p={},s=[],c={toc:s},f="wrapper";function u(e){let{components:t,...r}=e;return(0,o.kt)(f,(0,n.Z)({},c,r,{components:t,mdxType:"MDXLayout"}),(0,o.kt)("h1",{id:"profile-introduction"},"Profile Introduction"),(0,o.kt)("p",null,"Minder allows you to define profiles for your software supply chain."),(0,o.kt)("p",null,"The anatomy of a profile is the profile itself, which outlines the rules to be\nchecked, the rule types, and the evaluation engine."),(0,o.kt)("p",null,"As of time of writing, Minder supports the following evaluation engines:"),(0,o.kt)("ul",null,(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("strong",{parentName:"li"},(0,o.kt)("a",{parentName:"strong",href:"https://www.openprofileagent.org/"},"Open Profile Agent"))," (OPA) profile language."),(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("strong",{parentName:"li"},(0,o.kt)("a",{parentName:"strong",href:"https://jqlang.github.io/jq/"},"JQ"))," - a lightweight and flexible command-line JSON processor.")),(0,o.kt)("p",null,"Each engine is designed to be extensible, allowing you to integrate your own\nlogic and processes."),(0,o.kt)("p",null,"Please see the ",(0,o.kt)("a",{parentName:"p",href:"https://github.com/stacklok/minder/tree/main/examples"},"examples")," directory for examples of profiles, and ",(0,o.kt)("a",{parentName:"p",href:"/profile_engine/manage_profiles"},"Manage Profiles")," for more details on how to set up profiles and rule types."))}u.isMDXComponent=!0}}]);