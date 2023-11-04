"use strict";(self.webpackChunkstacklok=self.webpackChunkstacklok||[]).push([[3320],{3905:(e,t,a)=>{a.d(t,{Zo:()=>p,kt:()=>g});var r=a(67294);function n(e,t,a){return t in e?Object.defineProperty(e,t,{value:a,enumerable:!0,configurable:!0,writable:!0}):e[t]=a,e}function o(e,t){var a=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),a.push.apply(a,r)}return a}function i(e){for(var t=1;t<arguments.length;t++){var a=null!=arguments[t]?arguments[t]:{};t%2?o(Object(a),!0).forEach((function(t){n(e,t,a[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(a)):o(Object(a)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(a,t))}))}return e}function s(e,t){if(null==e)return{};var a,r,n=function(e,t){if(null==e)return{};var a,r,n={},o=Object.keys(e);for(r=0;r<o.length;r++)a=o[r],t.indexOf(a)>=0||(n[a]=e[a]);return n}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)a=o[r],t.indexOf(a)>=0||Object.prototype.propertyIsEnumerable.call(e,a)&&(n[a]=e[a])}return n}var l=r.createContext({}),c=function(e){var t=r.useContext(l),a=t;return e&&(a="function"==typeof e?e(t):i(i({},t),e)),a},p=function(e){var t=c(e.components);return r.createElement(l.Provider,{value:t},e.children)},u="mdxType",d={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},m=r.forwardRef((function(e,t){var a=e.components,n=e.mdxType,o=e.originalType,l=e.parentName,p=s(e,["components","mdxType","originalType","parentName"]),u=c(a),m=n,g=u["".concat(l,".").concat(m)]||u[m]||d[m]||o;return a?r.createElement(g,i(i({ref:t},p),{},{components:a})):r.createElement(g,i({ref:t},p))}));function g(e,t){var a=arguments,n=t&&t.mdxType;if("string"==typeof e||n){var o=a.length,i=new Array(o);i[0]=m;var s={};for(var l in t)hasOwnProperty.call(t,l)&&(s[l]=t[l]);s.originalType=e,s[u]="string"==typeof e?e:n,i[1]=s;for(var c=2;c<o;c++)i[c]=a[c];return r.createElement.apply(null,i)}return r.createElement.apply(null,a)}m.displayName="MDXCreateElement"},71693:(e,t,a)=>{a.r(t),a.d(t,{assets:()=>l,contentTitle:()=>i,default:()=>d,frontMatter:()=>o,metadata:()=>s,toc:()=>c});var r=a(87462),n=(a(67294),a(3905));const o={title:"Roadmap",sidebar_position:70},i="Roadmap",s={unversionedId:"understand/roadmap",id:"understand/roadmap",title:"Roadmap",description:"About this roadmap",source:"@site/docs/understand/roadmap.md",sourceDirName:"understand",slug:"/understand/roadmap",permalink:"/understand/roadmap",draft:!1,tags:[],version:"current",sidebarPosition:70,frontMatter:{title:"Roadmap",sidebar_position:70},sidebar:"minder",previous:{title:"Minder alerts",permalink:"/understand/alerts"},next:{title:"Frequently Asked Questions",permalink:"/understand/faq"}},l={},c=[{value:"About this roadmap",id:"about-this-roadmap",level:2},{value:"How to contribute",id:"how-to-contribute",level:2},{value:"In progress",id:"in-progress",level:2},{value:"Next",id:"next",level:2},{value:"Future considerations",id:"future-considerations",level:2}],p={toc:c},u="wrapper";function d(e){let{components:t,...a}=e;return(0,n.kt)(u,(0,r.Z)({},p,a,{components:t,mdxType:"MDXLayout"}),(0,n.kt)("h1",{id:"roadmap"},"Roadmap"),(0,n.kt)("h2",{id:"about-this-roadmap"},"About this roadmap"),(0,n.kt)("p",null,"This roadmap should serve as a reference point for Minder users and community members to understand where the project is heading. The roadmap is where you can learn about what features we're working on, what stage they're in, and when we expect to bring them to you. Priorities and requirements may change based on community feedback, roadblocks encountered, community contributions, and other factors. If you depend on a specific item, we encourage you to reach out to Stacklok to get updated status information, or help us deliver that feature by contributing to Minder."),(0,n.kt)("h2",{id:"how-to-contribute"},"How to contribute"),(0,n.kt)("p",null,"Have any questions or comments about items on the Minder roadmap? Share your feedback via ","[TBD]",". Interested in contributing to Minder? ","[Do this - TBD]","."),(0,n.kt)("p",null,(0,n.kt)("em",{parentName:"p"},"Last updated: November 2023")),(0,n.kt)("h2",{id:"in-progress"},"In progress"),(0,n.kt)("ul",null,(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Report CVEs, Trusty scores, and license info for dependencies in connected repos (with drift detection):")," Identify dependencies in connected GitHub repositories and show CVEs, Trusty scores, and license information including any changes over time."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Additional policy capabilities to improve user experience:")," Add the ability to edit/update policies, and provide a policy violation event stream that provides additional detail beyond the latest status."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Manage access policies with built-in roles:")," Assign users a built-in role (e.g., admin, edit, view) on a resource managed in Minder."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Create Project(s) and add repos (domain model):")," Group multiple GitHub repositories into a Project to simplify policy management."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Register an entire org to automatically add new repos:")," Register an entire GitHub organization instead of a single repo; any newly created repos will automatically be added to Minder to simplify policy management."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Automate the signing of packages to ensure they are tamper-proof:")," Use Sigstore to sign packages and containers based on policy.")),(0,n.kt)("h2",{id:"next"},"Next"),(0,n.kt)("ul",null,(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Report CVEs, Trusty scores, and license info for ingested SBOMs:")," Ingest SBOMS and identify dependencies; show CVEs, Trusty scores, and license information including any changes over time."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Block PRs based on Trusty scores:")," In addition to adding comments to pull requests (as is currently available), add the option to block pull requests as a policy remediation."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Create policy to manage licenses in PRs:")," Add a rule type to block and/or add comments to pull requests based on the licenses of the dependencies they import."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Automate the generation and signing of SLSA provenance statements:")," Enable users to generate SLSA provenance statements (e.g. through SLSA GitHub generator) and sign them with Sigstore."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Export a Minder 'badge/certification' that shows what practices a project followed:")," Create a badge that OSS maintainers and enterprise developers can create and share with others that asserts the Minder practices and policies their projects follow.")),(0,n.kt)("h2",{id:"future-considerations"},"Future considerations"),(0,n.kt)("ul",null,(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Enroll GitLab and Bitbucket repositories:")," In addition to managing GitHub repositories, enable users to manage configuration and policy for other providers."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Temporary permissions to providers vs. long-running:")," Policy remediation currently requires long-running permissions to providers such as GitHub; provide the option to enable temporary permissions."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Create nested hierarchy of Projects:")," Enable users to create multiple levels of Projects, where policies are inherited through levels of the tree, to simplify policy management."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Move a resource or Project between Projects:")," Enable users to move resources from one Project to another, and update policies accordingly."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Create PRs for dependency updates:")," As a policy autoremediation option, enable Minder to automatically create pull requests to update dependencies based on vulnerabilities, Trusty scores, or license changes."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Drive policy through git (config management):")," Enable users to dynamically create and maintain policies from other sources, e.g. Git, allowing for easier policy maintenance and the ability to manage policies through GitOps workflows."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Ensure a project has a license:")," A check that determines if a project has published a license."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Perform check for basic repo config:")," A check that determines if a repository has basic user-specified configuration applied, e.g. public/private, default branch name."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Run package behavior analysis tool:")," Enable a policy to continually run the ",(0,n.kt)("a",{parentName:"li",href:"https://github.com/ossf/package-analysis"},"OSSF Package Analysis tool"),", which analyzes the capabilities of packages available on open source repositories. The project looks for behaviors that indicate malicious software and  tracks changes in how packages behave over time, to identify when previously safe software begins acting suspiciously."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Help package authors improve Activity score in Trusty:")," Provide guidance and/or policy to improve key Trusty Activity score features (e.g., open issues, active contributors)."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Help package authors improve Risk Flags score in Trusty:")," Provide guidance and/or policy to improve key Trusty Risk Flags score features (e.g., package description, versions)."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Enable secrets scanning and code scanning with additional open source and commercial tools:")," Provide integrations to run scanning tools automatically from Minder (e.g. Synk, Trivy)."),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("strong",{parentName:"li"},"Generate SBOMs:")," Enable users to automatically create and sign SBOMs.")))}d.isMDXComponent=!0}}]);