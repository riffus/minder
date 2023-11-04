"use strict";(self.webpackChunkstacklok=self.webpackChunkstacklok||[]).push([[5216],{3905:(e,r,t)=>{t.d(r,{Zo:()=>u,kt:()=>f});var n=t(67294);function i(e,r,t){return r in e?Object.defineProperty(e,r,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[r]=t,e}function o(e,r){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);r&&(n=n.filter((function(r){return Object.getOwnPropertyDescriptor(e,r).enumerable}))),t.push.apply(t,n)}return t}function a(e){for(var r=1;r<arguments.length;r++){var t=null!=arguments[r]?arguments[r]:{};r%2?o(Object(t),!0).forEach((function(r){i(e,r,t[r])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):o(Object(t)).forEach((function(r){Object.defineProperty(e,r,Object.getOwnPropertyDescriptor(t,r))}))}return e}function l(e,r){if(null==e)return{};var t,n,i=function(e,r){if(null==e)return{};var t,n,i={},o=Object.keys(e);for(n=0;n<o.length;n++)t=o[n],r.indexOf(t)>=0||(i[t]=e[t]);return i}(e,r);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(n=0;n<o.length;n++)t=o[n],r.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(i[t]=e[t])}return i}var s=n.createContext({}),p=function(e){var r=n.useContext(s),t=r;return e&&(t="function"==typeof e?e(r):a(a({},r),e)),t},u=function(e){var r=p(e.components);return n.createElement(s.Provider,{value:r},e.children)},c="mdxType",d={inlineCode:"code",wrapper:function(e){var r=e.children;return n.createElement(n.Fragment,{},r)}},g=n.forwardRef((function(e,r){var t=e.components,i=e.mdxType,o=e.originalType,s=e.parentName,u=l(e,["components","mdxType","originalType","parentName"]),c=p(t),g=i,f=c["".concat(s,".").concat(g)]||c[g]||d[g]||o;return t?n.createElement(f,a(a({ref:r},u),{},{components:t})):n.createElement(f,a({ref:r},u))}));function f(e,r){var t=arguments,i=r&&r.mdxType;if("string"==typeof e||i){var o=t.length,a=new Array(o);a[0]=g;var l={};for(var s in r)hasOwnProperty.call(r,s)&&(l[s]=r[s]);l.originalType=e,l[c]="string"==typeof e?e:i,a[1]=l;for(var p=2;p<o;p++)a[p]=t[p];return n.createElement.apply(null,a)}return n.createElement.apply(null,t)}g.displayName="MDXCreateElement"},23042:(e,r,t)=>{t.r(r),t.d(r,{assets:()=>s,contentTitle:()=>a,default:()=>d,frontMatter:()=>o,metadata:()=>l,toc:()=>p});var n=t(87462),i=(t(67294),t(3905));const o={title:"Registering repositories and creating profiles",sidebar_position:10},a=void 0,l={unversionedId:"tutorials/register_repo_create_profile",id:"tutorials/register_repo_create_profile",title:"Registering repositories and creating profiles",description:"Goal",source:"@site/docs/tutorials/register_repo_create_profile.md",sourceDirName:"tutorials",slug:"/tutorials/register_repo_create_profile",permalink:"/tutorials/register_repo_create_profile",draft:!1,tags:[],version:"current",sidebarPosition:10,frontMatter:{title:"Registering repositories and creating profiles",sidebar_position:10},sidebar:"minder",previous:{title:"Minder DB schema",permalink:"/ref/schema"},next:{title:"Automatic Remediations",permalink:"/tutorials/remediations"}},s={},p=[{value:"Goal",id:"goal",level:2},{value:"Prerequisites",id:"prerequisites",level:2},{value:"Enroll a provider",id:"enroll-a-provider",level:2},{value:"Register repositories",id:"register-repositories",level:2},{value:"Creating and applying profiles",id:"creating-and-applying-profiles",level:2},{value:"Viewing alerts",id:"viewing-alerts",level:2},{value:"Delete registered repositories",id:"delete-registered-repositories",level:2}],u={toc:p},c="wrapper";function d(e){let{components:r,...t}=e;return(0,i.kt)(c,(0,n.Z)({},u,t,{components:r,mdxType:"MDXLayout"}),(0,i.kt)("h2",{id:"goal"},"Goal"),(0,i.kt)("p",null,"The goal of this tutorial is to register a GitHub repository, and create a profile that checks if secret scanning\nis enabled on the registered repository."),(0,i.kt)("h2",{id:"prerequisites"},"Prerequisites"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},"The ",(0,i.kt)("inlineCode",{parentName:"li"},"minder")," CLI application"),(0,i.kt)("li",{parentName:"ul"},"For enrolling an organization, a GitHub account that is either an Owner in the organization or an Admin on the repositories")),(0,i.kt)("h2",{id:"enroll-a-provider"},"Enroll a provider"),(0,i.kt)("p",null,"The first step is to tell Minder where to find your repositories.",(0,i.kt)("br",{parentName:"p"}),"\n","You do that by enrolling a provider."),(0,i.kt)("p",null,"In the example below, the chosen provider is GitHub, as indicated by the ",(0,i.kt)("inlineCode",{parentName:"p"},"--provider")," flag.",(0,i.kt)("br",{parentName:"p"}),"\n","This will allow you to later enroll your account's repositories."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"minder provider enroll --provider github\n")),(0,i.kt)("p",null,"This command will open a window in your browser, prompting you to authorize Minder to access some data on GitHub."),(0,i.kt)("p",null,"When enrolling an organization, use the ",(0,i.kt)("inlineCode",{parentName:"p"},"--owner")," flag of the ",(0,i.kt)("inlineCode",{parentName:"p"},"minder provider enroll")," command to specify the organization name:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"minder provider enroll --provider github --owner test-org\n")),(0,i.kt)("p",null,"The ",(0,i.kt)("inlineCode",{parentName:"p"},"--owner")," flag is not required when enrolling repositories from your personal account."),(0,i.kt)("p",null,"Note: If you are enrolling an organization, the account you use to enroll must be an Owner in the organization\nor an Admin on the repositories you will be registering."),(0,i.kt)("h2",{id:"register-repositories"},"Register repositories"),(0,i.kt)("p",null,"Once you have enrolled a provider, you can register repositories from that provider."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"minder repo register --provider github\n")),(0,i.kt)("p",null,"This command will show a list of the public repositories available for registration."),(0,i.kt)("p",null,"Navigate through the repositories using the arrow keys and select one or more repositories for registration\nby using the space key.",(0,i.kt)("br",{parentName:"p"}),"\n","Press the enter key once you have selected all the desired repositories."),(0,i.kt)("p",null,"You can see the list of repositories registered in Minder."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"minder repo list --provider github\n")),(0,i.kt)("h2",{id:"creating-and-applying-profiles"},"Creating and applying profiles"),(0,i.kt)("p",null,"A profile is a set of rules that you apply to your registered repositories.\nBefore creating a profile, you need to ensure that all desired rule_types have been created in Minder."),(0,i.kt)("p",null,"Start by creating a rule that checks if secret scanning is enabled and creates a security advisory\nif secret scanning is not enabled.",(0,i.kt)("br",{parentName:"p"}),"\n","This is a reference rule provider by the Minder team."),(0,i.kt)("p",null,"Fetch all the reference rules by cloning the ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/stacklok/minder-rules-and-profiles"},"minder-rules-and-profiles repository"),"."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"git clone https://github.com/stacklok/minder-rules-and-profiles.git\n")),(0,i.kt)("p",null,"In that directory you can find all the reference rules and profiles."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"cd minder-rules-and-profiles\n")),(0,i.kt)("p",null,"Create the ",(0,i.kt)("inlineCode",{parentName:"p"},"secret_scanning")," rule type in Minder:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"minder rule_type create -f rule-types/github/secret_scanning.yaml\n")),(0,i.kt)("p",null,"Next, create a profile that applies the secret scanning rule."),(0,i.kt)("p",null,"Create a new file called ",(0,i.kt)("inlineCode",{parentName:"p"},"profile.yaml"),".\nPaste the following profile definition into the newly created file."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},'---\nversion: v1\ntype: profile\nname: github-profile\ncontext:\n  provider: github\nalert: "on"\nremediate: "off"\nrepository:\n  - type: secret_scanning\n    def:\n      enabled: true\n')),(0,i.kt)("p",null,"Create the profile in Minder:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"minder profile create -f profile.yaml\n")),(0,i.kt)("p",null,"Check the status of the profile:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"minder profile_status list --profile github-profile\n")),(0,i.kt)("p",null,"If all registered repositories have secret scanning enabled, you will see the ",(0,i.kt)("inlineCode",{parentName:"p"},"OVERALL STATUS")," is ",(0,i.kt)("inlineCode",{parentName:"p"},"Success"),", otherwise the\noverall status is ",(0,i.kt)("inlineCode",{parentName:"p"},"Failure"),"."),(0,i.kt)("p",null,"See a detailed view of which repositories satisfy the secret scanning rule:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"minder profile_status list --profile github-profile --detailed\n")),(0,i.kt)("h2",{id:"viewing-alerts"},"Viewing alerts"),(0,i.kt)("p",null,"Disable secret scanning in one of the registered repositories, by following these\n",(0,i.kt)("a",{parentName:"p",href:"https://docs.github.com/en/code-security/secret-scanning/configuring-secret-scanning-for-your-repositories"},"instructions"),"\nprovided by GitHub."),(0,i.kt)("p",null,"Navigate to the repository on GitHub, click on the Security tab and view the Security Advisories.",(0,i.kt)("br",{parentName:"p"}),"\n","Notice that there is a new advisory titled ",(0,i.kt)("inlineCode",{parentName:"p"},"minder: profile github-profile failed with rule secret_scanning"),"."),(0,i.kt)("p",null,"Enable secret scanning in the same registered repository, by following these\n",(0,i.kt)("a",{parentName:"p",href:"https://docs.github.com/en/code-security/secret-scanning/configuring-secret-scanning-for-your-repositories"},"instructions"),"\nprovided by GitHub."),(0,i.kt)("p",null,"Navigate to the repository on GitHub, click on the Security tab and view the Security Advisories.\nNotice that the advisory titled ",(0,i.kt)("inlineCode",{parentName:"p"},"minder: profile github-profile failed with rule secret_scanning")," is now closed."),(0,i.kt)("h2",{id:"delete-registered-repositories"},"Delete registered repositories"),(0,i.kt)("p",null,"If you wish to delete a registered repository, you can do so with the following command:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"minder repo delete -n $REPO_NAME --provider github\n")),(0,i.kt)("p",null,"where ",(0,i.kt)("inlineCode",{parentName:"p"},"$REPO_NAME")," is the fully-qualified name (",(0,i.kt)("inlineCode",{parentName:"p"},"owner/name"),") of the repository you wish to delete, for example ",(0,i.kt)("inlineCode",{parentName:"p"},"testorg/testrepo"),"."))}d.isMDXComponent=!0}}]);