"use strict";(self.webpackChunkstacklok=self.webpackChunkstacklok||[]).push([[6237],{3905:(e,t,n)=>{n.d(t,{Zo:()=>c,kt:()=>k});var a=n(67294);function r(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function i(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);t&&(a=a.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,a)}return n}function l(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?i(Object(n),!0).forEach((function(t){r(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):i(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function o(e,t){if(null==e)return{};var n,a,r=function(e,t){if(null==e)return{};var n,a,r={},i=Object.keys(e);for(a=0;a<i.length;a++)n=i[a],t.indexOf(n)>=0||(r[n]=e[n]);return r}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(a=0;a<i.length;a++)n=i[a],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(r[n]=e[n])}return r}var s=a.createContext({}),p=function(e){var t=a.useContext(s),n=t;return e&&(n="function"==typeof e?e(t):l(l({},t),e)),n},c=function(e){var t=p(e.components);return a.createElement(s.Provider,{value:t},e.children)},u="mdxType",d={inlineCode:"code",wrapper:function(e){var t=e.children;return a.createElement(a.Fragment,{},t)}},m=a.forwardRef((function(e,t){var n=e.components,r=e.mdxType,i=e.originalType,s=e.parentName,c=o(e,["components","mdxType","originalType","parentName"]),u=p(n),m=r,k=u["".concat(s,".").concat(m)]||u[m]||d[m]||i;return n?a.createElement(k,l(l({ref:t},c),{},{components:n})):a.createElement(k,l({ref:t},c))}));function k(e,t){var n=arguments,r=t&&t.mdxType;if("string"==typeof e||r){var i=n.length,l=new Array(i);l[0]=m;var o={};for(var s in t)hasOwnProperty.call(t,s)&&(o[s]=t[s]);o.originalType=e,o[u]="string"==typeof e?e:r,l[1]=o;for(var p=2;p<i;p++)l[p]=n[p];return a.createElement.apply(null,l)}return a.createElement.apply(null,n)}m.displayName="MDXCreateElement"},63074:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>s,contentTitle:()=>l,default:()=>d,frontMatter:()=>i,metadata:()=>o,toc:()=>p});var a=n(87462),r=(n(67294),n(3905));const i={title:"Run the Server",sidebar_position:10},l="Run a minder server",o={unversionedId:"run_mediator_server/run_the_server",id:"run_mediator_server/run_the_server",title:"Run the Server",description:"Minder is platform, comprising of a controlplane, a CLI, a database and an identity provider.",source:"@site/docs/run_mediator_server/run_the_server.md",sourceDirName:"run_mediator_server",slug:"/run_mediator_server/run_the_server",permalink:"/run_mediator_server/run_the_server",draft:!1,tags:[],version:"current",sidebarPosition:10,frontMatter:{title:"Run the Server",sidebar_position:10},sidebar:"mediator",previous:{title:"Manage profiles and violations",permalink:"/profile_engine/manage_profiles"},next:{title:"Configure OAuth Provider",permalink:"/run_mediator_server/config_oauth"}},s={},p=[{value:"Prerequisites",id:"prerequisites",level:2},{value:"Download the latest release",id:"download-the-latest-release",level:2},{value:"Build from source",id:"build-from-source",level:2},{value:"Clone the repository",id:"clone-the-repository",level:3},{value:"Build the application",id:"build-the-application",level:3},{value:"Database creation",id:"database-creation",level:2},{value:"Using a container",id:"using-a-container",level:3},{value:"Create the database",id:"create-the-database",level:3},{value:"Identity Provider",id:"identity-provider",level:2},{value:"Using a container",id:"using-a-container-1",level:3},{value:"Social login",id:"social-login",level:3},{value:"Create a GitHub OAuth Application",id:"create-a-github-oauth-application",level:4},{value:"Enable GitHub login",id:"enable-github-login",level:4},{value:"Create encryption keys",id:"create-encryption-keys",level:2},{value:"Run the application",id:"run-the-application",level:2}],c={toc:p},u="wrapper";function d(e){let{components:t,...i}=e;return(0,r.kt)(u,(0,a.Z)({},c,i,{components:t,mdxType:"MDXLayout"}),(0,r.kt)("h1",{id:"run-a-minder-server"},"Run a minder server"),(0,r.kt)("p",null,"Minder is platform, comprising of a controlplane, a CLI, a database and an identity provider."),(0,r.kt)("p",null,"The control plane runs two endpoints, a gRPC endpoint and a HTTP endpoint."),(0,r.kt)("p",null,"Minder is controlled and managed via the CLI application ",(0,r.kt)("inlineCode",{parentName:"p"},"minder"),"."),(0,r.kt)("p",null,"PostgreSQL is used as the database."),(0,r.kt)("p",null,"Keycloak is used as the identity provider."),(0,r.kt)("p",null,"There are two methods to get started with Mediator, either by downloading the\nlatest release, building from source or (quickest) using the provided ",(0,r.kt)("inlineCode",{parentName:"p"},"docker-compose"),"\nfile."),(0,r.kt)("h2",{id:"prerequisites"},"Prerequisites"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("a",{parentName:"li",href:"https://golang.org/doc/install"},"Go 1.20")),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("a",{parentName:"li",href:"https://www.postgresql.org/download/"},"PostgreSQL")),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("a",{parentName:"li",href:"https://www.keycloak.org/guides"},"Keycloak"))),(0,r.kt)("h2",{id:"download-the-latest-release"},"Download the latest release"),(0,r.kt)("p",null,"[stub for when we cut a first release]"),(0,r.kt)("h2",{id:"build-from-source"},"Build from source"),(0,r.kt)("p",null,"Alternatively, you can build from source."),(0,r.kt)("h3",{id:"clone-the-repository"},"Clone the repository"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"git clone git@github.com:stacklok/mediator.git\n")),(0,r.kt)("h3",{id:"build-the-application"},"Build the application"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"make build\n")),(0,r.kt)("p",null,"This will create two binaries, ",(0,r.kt)("inlineCode",{parentName:"p"},"bin/mediator-server")," and ",(0,r.kt)("inlineCode",{parentName:"p"},"bin/minder"),"."),(0,r.kt)("p",null,"You may now copy these into a location on your path, or run them directly from the ",(0,r.kt)("inlineCode",{parentName:"p"},"bin")," directory."),(0,r.kt)("p",null,"You will also need a configuration file. You can copy the example configuration file from ",(0,r.kt)("inlineCode",{parentName:"p"},"configs/config.yaml.example")," to ",(0,r.kt)("inlineCode",{parentName:"p"},"$(PWD)/config.yaml"),"."),(0,r.kt)("p",null,"If you prefer to use a different file name or location, you can specify this using the ",(0,r.kt)("inlineCode",{parentName:"p"},"--config"),"\nflag, e.g. ",(0,r.kt)("inlineCode",{parentName:"p"},"mediator-server --config /file/path/mediator.yaml serve")," when you later run the application."),(0,r.kt)("h2",{id:"database-creation"},"Database creation"),(0,r.kt)("p",null,"Mediator requires a PostgreSQL database to be running. You can install this locally, or use a container."),(0,r.kt)("p",null,"Should you install locally, you will need to set certain configuration options in your ",(0,r.kt)("inlineCode",{parentName:"p"},"config.yaml")," file, to reflect your local database configuration."),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-yaml"},'database:\n  dbhost: "localhost"\n  dbport: 5432\n  dbuser: postgres\n  dbpass: postgres\n  dbname: mediator\n  sslmode: disable\n')),(0,r.kt)("h3",{id:"using-a-container"},"Using a container"),(0,r.kt)("p",null,"A simple way to get started is to use the provided ",(0,r.kt)("inlineCode",{parentName:"p"},"docker-compose")," file."),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"docker-compose up -d postgres\n")),(0,r.kt)("h3",{id:"create-the-database"},"Create the database"),(0,r.kt)("p",null,"Once you have a running database, you can create the database using the ",(0,r.kt)("inlineCode",{parentName:"p"},"mediator-server")," CLI tool or via the ",(0,r.kt)("inlineCode",{parentName:"p"},"make")," command."),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"make migrateup\n")),(0,r.kt)("p",null,"or:"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"mediator-server migrate up\n")),(0,r.kt)("h2",{id:"identity-provider"},"Identity Provider"),(0,r.kt)("p",null,"Mediator requires a Keycloak instance to be running. You can install this locally, or use a container."),(0,r.kt)("p",null,"Should you install locally, you will need to configure the client on Keycloak.\nYou will need the following:"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},'A Keycloak realm with event saving turned on for the "Delete account" event.'),(0,r.kt)("li",{parentName:"ul"},"A registered public client with the redirect URI ",(0,r.kt)("inlineCode",{parentName:"li"},"http://localhost/*"),". This is used for the mediator CLI."),(0,r.kt)("li",{parentName:"ul"},"A registered confidential client with a service account that can manage users and view events. This is used for the mediator server.")),(0,r.kt)("p",null,"You will also need to set certain configuration options in your ",(0,r.kt)("inlineCode",{parentName:"p"},"config.yaml")," file, to reflect your local Keycloak configuration."),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-yaml"},"identity:\n  cli:\n    issuer_url: http://localhost:8081\n    realm: stacklok\n    client_id: mediator-cli\n  server:\n    issuer_url: http://localhost:8081\n    realm: stacklok\n    client_id: mediator-server\n    client_secret: secret\n")),(0,r.kt)("h3",{id:"using-a-container-1"},"Using a container"),(0,r.kt)("p",null,"A simple way to get started is to use the provided ",(0,r.kt)("inlineCode",{parentName:"p"},"docker-compose")," file."),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"docker-compose up -d keycloak\n")),(0,r.kt)("h3",{id:"social-login"},"Social login"),(0,r.kt)("p",null,"Once you have a Keycloak instance running locally, you can set up GitHub authentication."),(0,r.kt)("h4",{id:"create-a-github-oauth-application"},"Create a GitHub OAuth Application"),(0,r.kt)("ol",null,(0,r.kt)("li",{parentName:"ol"},"Navigate to ",(0,r.kt)("a",{parentName:"li",href:"https://github.com/settings/profile"},"GitHub Developer Settings")),(0,r.kt)("li",{parentName:"ol"},'Select "Developer Settings" from the left hand menu'),(0,r.kt)("li",{parentName:"ol"},'Select "OAuth Apps" from the left hand menu'),(0,r.kt)("li",{parentName:"ol"},'Select "New OAuth App"'),(0,r.kt)("li",{parentName:"ol"},"Enter the following details:",(0,r.kt)("ul",{parentName:"li"},(0,r.kt)("li",{parentName:"ul"},"Application Name: ",(0,r.kt)("inlineCode",{parentName:"li"},"Stacklok Identity Provider")),(0,r.kt)("li",{parentName:"ul"},"Homepage URL: ",(0,r.kt)("inlineCode",{parentName:"li"},"http://localhost:8081")," or the URL you specified as the ",(0,r.kt)("inlineCode",{parentName:"li"},"issuer_url")," in your ",(0,r.kt)("inlineCode",{parentName:"li"},"config.yaml")),(0,r.kt)("li",{parentName:"ul"},"Authorization callback URL: ",(0,r.kt)("inlineCode",{parentName:"li"},"http://localhost:8081/realms/stacklok/broker/github/endpoint")))),(0,r.kt)("li",{parentName:"ol"},'Select "Register Application"'),(0,r.kt)("li",{parentName:"ol"},"Generate a client secret")),(0,r.kt)("p",null,(0,r.kt)("img",{alt:"github oauth2 page",src:n(97368).Z,width:"3024",height:"2984"})),(0,r.kt)("h4",{id:"enable-github-login"},"Enable GitHub login"),(0,r.kt)("p",null,"Using the client ID and client secret you created above, enable GitHub login your local Keycloak instance by running the\nfollowing command:"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"make KC_GITHUB_CLIENT_ID=<client_id> KC_GITHUB_CLIENT_SECRET=<client_secret> github-login\n")),(0,r.kt)("h2",{id:"create-encryption-keys"},"Create encryption keys"),(0,r.kt)("p",null,"The default configuration expects these keys to be in a directory named ",(0,r.kt)("inlineCode",{parentName:"p"},".ssh"),", relative to where you run the ",(0,r.kt)("inlineCode",{parentName:"p"},"mediator-server")," binary.\nStart by creating the ",(0,r.kt)("inlineCode",{parentName:"p"},".ssh")," directory."),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"mkdir .ssh && cd .ssh\n")),(0,r.kt)("p",null,"You can create the encryption keys using the ",(0,r.kt)("inlineCode",{parentName:"p"},"openssl")," CLI tool."),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"# First generate an RSA key pair\nssh-keygen -t rsa -b 2048 -m PEM -f access_token_rsa\nssh-keygen -t rsa -b 2048 -m PEM -f refresh_token_rsa\n# For passwordless keys, run the following:\nopenssl rsa -in access_token_rsa -pubout -outform PEM -out access_token_rsa.pub\nopenssl rsa -in access_token_rsa -pubout -outform PEM -out access_token_rsa.pub\n")),(0,r.kt)("p",null,"If your keys live in a directory other than ",(0,r.kt)("inlineCode",{parentName:"p"},".ssh"),", you can specify the location of the keys in the ",(0,r.kt)("inlineCode",{parentName:"p"},"config.yaml")," file."),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-yaml"},'auth:\n  access_token_private_key: "./.ssh/access_token_rsa"\n  access_token_public_key: "./.ssh/access_token_rsa.pub"\n  refresh_token_private_key: "./.ssh/refresh_token_rsa"\n  refresh_token_public_key: "./.ssh/refresh_token_rsa.pub"\n')),(0,r.kt)("h2",{id:"run-the-application"},"Run the application"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"mediator-server serve\n")),(0,r.kt)("p",null,"The application will be available on ",(0,r.kt)("inlineCode",{parentName:"p"},"http://localhost:8080")," and gRPC on ",(0,r.kt)("inlineCode",{parentName:"p"},"localhost:8090"),"."))}d.isMDXComponent=!0},97368:(e,t,n)=>{n.d(t,{Z:()=>a});const a=n.p+"assets/images/github-settings-application-a77dd69170f082985a1fa8b217081efb.png"}}]);