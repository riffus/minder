"use strict";(self.webpackChunkstacklok=self.webpackChunkstacklok||[]).push([[4724],{3905:(e,t,n)=>{n.d(t,{Zo:()=>u,kt:()=>f});var r=n(67294);function i(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function a(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function o(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?a(Object(n),!0).forEach((function(t){i(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):a(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function l(e,t){if(null==e)return{};var n,r,i=function(e,t){if(null==e)return{};var n,r,i={},a=Object.keys(e);for(r=0;r<a.length;r++)n=a[r],t.indexOf(n)>=0||(i[n]=e[n]);return i}(e,t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(r=0;r<a.length;r++)n=a[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(i[n]=e[n])}return i}var s=r.createContext({}),p=function(e){var t=r.useContext(s),n=t;return e&&(n="function"==typeof e?e(t):o(o({},t),e)),n},u=function(e){var t=p(e.components);return r.createElement(s.Provider,{value:t},e.children)},d="mdxType",c={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},m=r.forwardRef((function(e,t){var n=e.components,i=e.mdxType,a=e.originalType,s=e.parentName,u=l(e,["components","mdxType","originalType","parentName"]),d=p(n),m=i,f=d["".concat(s,".").concat(m)]||d[m]||c[m]||a;return n?r.createElement(f,o(o({ref:t},u),{},{components:n})):r.createElement(f,o({ref:t},u))}));function f(e,t){var n=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var a=n.length,o=new Array(a);o[0]=m;var l={};for(var s in t)hasOwnProperty.call(t,s)&&(l[s]=t[s]);l.originalType=e,l[d]="string"==typeof e?e:i,o[1]=l;for(var p=2;p<a;p++)o[p]=n[p];return r.createElement.apply(null,o)}return r.createElement.apply(null,n)}m.displayName="MDXCreateElement"},74240:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>s,contentTitle:()=>o,default:()=>c,frontMatter:()=>a,metadata:()=>l,toc:()=>p});var r=n(87462),i=(n(67294),n(3905));const a={title:"Remediations",sidebar_position:40},o="Alerts and Automatic Remediation in Minder",l={unversionedId:"understand/remediation",id:"understand/remediation",title:"Remediations",description:"A profile in Minder offers a comprehensive view of your security posture, encompassing more than just the status report.",source:"@site/docs/understand/remediation.md",sourceDirName:"understand",slug:"/understand/remediation",permalink:"/understand/remediation",draft:!1,tags:[],version:"current",sidebarPosition:40,frontMatter:{title:"Remediations",sidebar_position:40},sidebar:"minder",previous:{title:"Security Model",permalink:"/understand/security"},next:{title:"Minder alerts",permalink:"/understand/alerts"}},s={},p=[{value:"Enabling alerts in a profile",id:"enabling-alerts-in-a-profile",level:3},{value:"Enabling remediations in a profile",id:"enabling-remediations-in-a-profile",level:3}],u={toc:p},d="wrapper";function c(e){let{components:t,...n}=e;return(0,i.kt)(d,(0,r.Z)({},u,n,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("h1",{id:"alerts-and-automatic-remediation-in-minder"},"Alerts and Automatic Remediation in Minder"),(0,i.kt)("p",null,"A profile in Minder offers a comprehensive view of your security posture, encompassing more than just the status report.\nIt actively responds to any rules that are not in compliance, taking specific actions. These actions can include the\ncreation of alerts for rules that have failed, as well as the execution of remediations to fix the non-compliant\naspects."),(0,i.kt)("p",null,"When alerting is turned on in a profile, Minder will open an alert to bring your attention to the non-compliance issue.\nConversely, when the rule evaluation passes, Minder will automatically close any previously opened alerts related to\nthat rule."),(0,i.kt)("p",null,"When remediation is turned on, Minder also supports the ability to automatically remediate failed rules based on their\ntype, i.e., by processing a REST call to enable/disable a non-compliant repository setting or creating a pull request\nwith a proposed fix. Note that not all rule types support automatic remediation yet."),(0,i.kt)("h3",{id:"enabling-alerts-in-a-profile"},"Enabling alerts in a profile"),(0,i.kt)("p",null,'To activate the alert feature within a profile, you need to adjust the YAML definition.\nSpecifically, you should set the alert parameter to "on":'),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},'alert: "on"\n')),(0,i.kt)("p",null,"Enabling alerts at the profile level means that for any rules included in the profile, alerts will be generated for\nany rule failures. For better clarity, consider this rule snippet:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},'---\nversion: v1\ntype: rule-type\nname: sample_rule\ndef:\n  alert:\n      type: security_advisory\n      security_advisory:\n        severity: "medium"\n')),(0,i.kt)("p",null,"In this example, the ",(0,i.kt)("inlineCode",{parentName:"p"},"sample_rule")," defines an alert action that creates a medium severity security advisory in the\nrepository for any non-compliant repositories."),(0,i.kt)("p",null,"Now, let's see how this works in practice within a profile. Consider the following profile configuration with alerts\nturned on:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},'version: v1\ntype: profile\nname: sample-profile\ncontext:\n  provider: github\nalert: "on"\nrepository:\n  - type: sample_rule\n    def:\n      enabled: true\n')),(0,i.kt)("p",null,"In this profile, all repositories that do not meet the conditions specified in the ",(0,i.kt)("inlineCode",{parentName:"p"},"sample_rule")," will automatically\ngenerate security advisories."),(0,i.kt)("h3",{id:"enabling-remediations-in-a-profile"},"Enabling remediations in a profile"),(0,i.kt)("p",null,'To activate the remediation feature within a profile, you need to adjust the YAML definition.\nSpecifically, you should set the remediate parameter to "on":'),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},'remediate: "on"\n')),(0,i.kt)("p",null,"Enabling remediation at the profile level means that for any rules included in the profile, a remediation action will be\ntaken for any rule failures."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},'---\nversion: v1\ntype: rule-type\nname: sample_rule\ndef:\n  remediate:\n    type: rest\n    rest:\n      method: PATCH\n      endpoint: "/repos/{{.Entity.Owner}}/{{.Entity.Name}}"\n      body: |\n        { "security_and_analysis": {"secret_scanning": { "status": "enabled" } } }\n')),(0,i.kt)("p",null,"In this example, the ",(0,i.kt)("inlineCode",{parentName:"p"},"sample_rule")," defines a remediation action that performs a PATCH request to an endpoint. This\nrequest will change the modify the state of the repository ensuring it complies with the rule."),(0,i.kt)("p",null,"Now, let's see how this works in practice within a profile. Consider the following profile configuration with\nremediation turned on:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},'version: v1\ntype: profile\nname: sample-profile\ncontext:\n  provider: github\nremediate: "on"\nrepository:\n  - type: sample_rule\n    def:\n      enabled: true\n')),(0,i.kt)("p",null,"In this profile, all repositories that do not meet the conditions specified in the ",(0,i.kt)("inlineCode",{parentName:"p"},"sample_rule")," will automatically\nreceive a PATCH request to the specified endpoint. This action will make the repository compliant."))}c.isMDXComponent=!0}}]);