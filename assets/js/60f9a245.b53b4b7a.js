"use strict";(self.webpackChunkstacklok=self.webpackChunkstacklok||[]).push([[8896],{3905:(e,t,n)=>{n.d(t,{Zo:()=>u,kt:()=>h});var r=n(67294);function i(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function a(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function o(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?a(Object(n),!0).forEach((function(t){i(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):a(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function l(e,t){if(null==e)return{};var n,r,i=function(e,t){if(null==e)return{};var n,r,i={},a=Object.keys(e);for(r=0;r<a.length;r++)n=a[r],t.indexOf(n)>=0||(i[n]=e[n]);return i}(e,t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(r=0;r<a.length;r++)n=a[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(i[n]=e[n])}return i}var s=r.createContext({}),p=function(e){var t=r.useContext(s),n=t;return e&&(n="function"==typeof e?e(t):o(o({},t),e)),n},u=function(e){var t=p(e.components);return r.createElement(s.Provider,{value:t},e.children)},c="mdxType",f={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},d=r.forwardRef((function(e,t){var n=e.components,i=e.mdxType,a=e.originalType,s=e.parentName,u=l(e,["components","mdxType","originalType","parentName"]),c=p(n),d=i,h=c["".concat(s,".").concat(d)]||c[d]||f[d]||a;return n?r.createElement(h,o(o({ref:t},u),{},{components:n})):r.createElement(h,o({ref:t},u))}));function h(e,t){var n=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var a=n.length,o=new Array(a);o[0]=d;var l={};for(var s in t)hasOwnProperty.call(t,s)&&(l[s]=t[s]);l.originalType=e,l[c]="string"==typeof e?e:i,o[1]=l;for(var p=2;p<a;p++)o[p]=n[p];return r.createElement.apply(null,o)}return r.createElement.apply(null,n)}d.displayName="MDXCreateElement"},73747:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>s,contentTitle:()=>o,default:()=>f,frontMatter:()=>a,metadata:()=>l,toc:()=>p});var r=n(87462),i=(n(67294),n(3905));const a={title:"Manage profiles and violations",sidebar_position:20},o="Manage profiles",l={unversionedId:"profile_engine/manage_profiles",id:"profile_engine/manage_profiles",title:"Manage profiles and violations",description:"In order to detect security deviations from repositories or other entities, Mediator is relying on the concepts of Profiles.",source:"@site/docs/profile_engine/manage_profiles.md",sourceDirName:"profile_engine",slug:"/profile_engine/manage_profiles",permalink:"/profile_engine/manage_profiles",draft:!1,tags:[],version:"current",sidebarPosition:20,frontMatter:{title:"Manage profiles and violations",sidebar_position:20},sidebar:"mediator",previous:{title:"Profile Introduction",permalink:"/profile_engine/profile_introduction"},next:{title:"Run the Server",permalink:"/run_mediator_server/run_the_server"}},s={},p=[{value:"Prerequisites",id:"prerequisites",level:2},{value:"List rule types",id:"list-rule-types",level:2},{value:"Create a rule type",id:"create-a-rule-type",level:2},{value:"Create a profile",id:"create-a-profile",level:2},{value:"List profile status",id:"list-profile-status",level:2}],u={toc:p},c="wrapper";function f(e){let{components:t,...n}=e;return(0,i.kt)(c,(0,r.Z)({},u,n,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("h1",{id:"manage-profiles"},"Manage profiles"),(0,i.kt)("p",null,"In order to detect security deviations from repositories or other entities, Mediator is relying on the concepts of ",(0,i.kt)("strong",{parentName:"p"},"Profiles"),".\nA profile is a definition of a verification we want to do on an entity in a pipeline.\nA ",(0,i.kt)("strong",{parentName:"p"},"profile")," is an instance of a profile type applied to an specific group, with the relevant settings filled in."),(0,i.kt)("p",null,"An example profile is the following:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},"---\nversion: v1\ntype: profile\nname: acme-github-profile\ncontext:\n  organization: ACME\n  group: Root Group\nrepository:\n  - context: github\n    rules:\n      - type: secret_scanning\n        def:\n          enabled: true\n      - type: branch_protection\n        params:\n          branch: main\n        def:\n          required_pull_request_reviews:\n            dismiss_stale_reviews: true\n            require_code_owner_reviews: true\n            required_approving_review_count: 1\n          required_linear_history: true\n          allow_force_pushes: false\n          allow_deletions: false\n          allow_fork_syncing: true\n")),(0,i.kt)("p",null,"The full example is available in the ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/stacklok/mediator/blob/main/examples/github/profiles/profile.yaml"},"examples directory"),"."),(0,i.kt)("p",null,"This profile is checking that secret scanning is enabled for all repositories belonging to the ACME organization,\nand that the ",(0,i.kt)("inlineCode",{parentName:"p"},"main")," branch is protected, requiring at least one approval from a code owner before landing a pull request."),(0,i.kt)("p",null,"You'll notice that this profile calls two different rules: ",(0,i.kt)("inlineCode",{parentName:"p"},"secret_scanning")," and ",(0,i.kt)("inlineCode",{parentName:"p"},"branch_protection"),"."),(0,i.kt)("p",null,"Rules can be instantiated from rule types, and they are the ones that are actually doing the verification."),(0,i.kt)("p",null,"A rule type is a definition of a verification we want to do on an entity in a pipeline."),(0,i.kt)("p",null,"An example rule type is the following:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},'---\nversion: v1\ntype: rule-type\nname: secret_scanning\ncontext:\n  provider: github\n  group: Root Group\ndescription: Verifies that secret scanning is enabled for a given repository.\ndef:\n  # Defines the section of the pipeline the rule will appear in.\n  # This will affect the template that is used to render multiple parts\n  # of the rule.\n  in_entity: repository\n  # Defines the schema for writing a rule with this rule being checked\n  rule_schema:\n    properties:\n      enabled:\n        type: boolean\n        default: true\n  # Defines the configuration for ingesting data relevant for the rule\n  ingest:\n    type: rest\n    rest:\n      # This is the path to the data source. Given that this will evaluate\n      # for each repository in the organization, we use a template that\n      # will be evaluated for each repository. The structure to use is the\n      # protobuf structure for the entity that is being evaluated.\n      endpoint: "/repos/{{.Entity.Owner}}/{{.Entity.Name}}"\n      # This is the method to use to retrieve the data. It should already default to JSON\n      parse: json\n  # Defines the configuration for evaluating data ingested against the given profile\n  eval:\n    type: jq\n    jq:\n      # Ingested points to the data retrieved in the `ingest` section\n      - ingested:\n          def: \'.security_and_analysis.secret_scanning.status == "enabled"\'\n        # profile points to the profile itself.\n        profile:\n          def: ".enabled"\n\n')),(0,i.kt)("p",null,"The full example is available in the ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/stacklok/mediator/tree/main/examples/github/rule-types"},"examples directory")),(0,i.kt)("p",null,"This rule type is checking that secret scanning is enabled for all repositories belonging to the ACME organization."),(0,i.kt)("p",null,"The rule type defines how the upstream GitHub API is to be queried, and how the data is to be evaluated.\nIt also defines how instances of this rule will be validated against the rule schema."),(0,i.kt)("p",null,"When a profile is created for an specific group, a continuous monitoring for the related objects start. An object can be a repository,\na branch, a package... depending on the profile definition. When an specific object is not matching what's expected,\na violation is presented via the profile's ",(0,i.kt)("strong",{parentName:"p"},"status"),". When a violation happens, the overall ",(0,i.kt)("strong",{parentName:"p"},"Profile status")," for this specific entity changes,\nbecoming failed. There is also individual statuses for each rule evaluation. User can check the reason for this violation and take remediation\nactions to comply with the profile."),(0,i.kt)("h2",{id:"prerequisites"},"Prerequisites"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},"The ",(0,i.kt)("inlineCode",{parentName:"li"},"minder")," CLI application"),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/getting_started/register_repos"},"At least one repository is registered for Mediator"))),(0,i.kt)("h2",{id:"list-rule-types"},"List rule types"),(0,i.kt)("p",null,"Covered rule types are now:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},"branch_protection: controls the branch protection rules on a repo"),(0,i.kt)("li",{parentName:"ul"},"secret_scanning: enforces secret scanning for a repo")),(0,i.kt)("p",null,"You can list all profile types registered in Mediator:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"minder rule_type list --provider github\n")),(0,i.kt)("p",null,"By default, a rule type is providing some recommended default values, so users can create profiles\nby using those defaults without having to create a new profile from scratch."),(0,i.kt)("h2",{id:"create-a-rule-type"},"Create a rule type"),(0,i.kt)("p",null,"Before creating a profile, we need to ensure that all rule types exist in mediator."),(0,i.kt)("p",null,"A rule type can be created by pointing to a directory (or file) containing the rule type definition:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"minder rule_type create -f ./examples/github/rule-types\n")),(0,i.kt)("p",null,"Where the yaml files in the directory ",(0,i.kt)("inlineCode",{parentName:"p"},"rule-types")," may look as the example above."),(0,i.kt)("p",null,"Once all the relevant rule types are available for our group, we may take them into use\nby creating a profile."),(0,i.kt)("h2",{id:"create-a-profile"},"Create a profile"),(0,i.kt)("p",null,"When there is a need to control the specific behaviours for a set of repositories, a profile can be\ncreated, based on the previous profile types."),(0,i.kt)("p",null,"A profile needs to be associated with a provider and a group ID, and it will be applied to all\nrepositories belonging to that group.\nThe profile can be created by using the provided defaults, or by providing a new one stored on a file."),(0,i.kt)("p",null,"For creating based on a file:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"minder profile create -f ./examples/github/profiles/profile.yaml\n")),(0,i.kt)("p",null,"Where ",(0,i.kt)("inlineCode",{parentName:"p"},"profile.yaml")," may look as the example above."),(0,i.kt)("p",null,"When an specific setting is not provided, the value of this setting is not compared against the profile.\nThis specific profile will monitor the ",(0,i.kt)("inlineCode",{parentName:"p"},"main")," branch for all related repositories, checking that pull request enforcement is on\nplace, requiring reviews from code owners and a minimum of 2 approvals before landing. It will also require\nthat force pushes and deletions are disabled for the ",(0,i.kt)("inlineCode",{parentName:"p"},"main")," branch."),(0,i.kt)("p",null,"When a profile for a provider and group is created, any repos registered for the same provider and group,\nare being observed. Each time that there is a change on the repo that causes the profile status to be updated."),(0,i.kt)("h2",{id:"list-profile-status"},"List profile status"),(0,i.kt)("p",null,"When there is an event that causes a profile violation, the violation is stored in the database, and the\noverall status of the profile for this specific repository is changed.\nProfile status will inform about:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},"profile_type (branch_protection...)"),(0,i.kt)("li",{parentName:"ul"},"status: ","[success, failure]"),(0,i.kt)("li",{parentName:"ul"},"last updated: time when this status was updated")),(0,i.kt)("p",null,"Profile status can be checked using the following commands"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"minder profile_status list --profile 1\n")),(0,i.kt)("p",null,"To view all of the rule evaluations, use the following"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"minder profile_status list --profile 1 --detailed\n")))}f.isMDXComponent=!0}}]);