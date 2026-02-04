6
2
0
2

b
e
F
1

]

R
C
.
s
c
[

1
v
9
2
1
1
0
.
2
0
6
2
:
v
i
X
r
a

SMCP: Secure Model Context Protocol
XINYI HOU∗, Huazhong University of Science and Technology, China
SHENAO WANG∗, Huazhong University of Science and Technology, China
YIFAN ZHANG, Huazhong University of Science and Technology, China
ZILUO XUE, Huazhong University of Science and Technology, China
YANJIE ZHAO, Huazhong University of Science and Technology, China
CAI FU, Huazhong University of Science and Technology, China
HAOYU WANG, Huazhong University of Science and Technology, China

Agentic AI systems built around large language models (LLMs) are moving away from closed, single-model
frameworks and toward open ecosystems that connect a variety of agents, external tools, and resources. The
Model Context Protocol (MCP) has emerged as a standard to unify tool access, allowing agents to discover,
invoke, and coordinate with tools more flexibly. However, as MCP becomes more widely adopted, it also
brings a new set of security and privacy challenges. These include risks such as unauthorized access, tool
poisoning, prompt injection, privilege escalation, and supply chain attacks, any of which can impact different
parts of the protocol workflow. While recent research has examined possible attack surfaces and suggested
targeted countermeasures, there is still a lack of systematic, protocol-level security improvements for MCP. To
address this, we introduce the Secure Model Context Protocol (SMCP), which builds on MCP by adding unified
identity management, robust mutual authentication, ongoing security context propagation, fine-grained policy
enforcement, and comprehensive audit logging. In this paper, we present the main components of SMCP,
explain how it helps reduce security risks, and illustrate its application with practical examples. We hope that
this work will contribute to the development of agentic systems that are not only powerful and adaptable, but
also secure and dependable.

1 Introduction
In recent years, rapid progress in general AI technologies, particularly advances in Large Language
Models (LLMs), has shifted agentic systems away from single-model conversation paradigms. In-
creasingly, these systems are moving toward open ecosystems that connect heterogeneous agents,
external tools, and diverse resources. LLM-powered autonomous agents now go beyond text gener-
ation but handle lots of real-world tasks by integrating modules for planning, memory, tool use,
and action execution. Because of these advances, LLMs are becoming critical entities capable of
continuous perception, decision-making, and action in complex environments, as demonstrated
in recent studies [19, 27, 28, 31]. At the same time, protocols designed for tool access and agent
communication have become increasingly important. Mechanisms such as OpenAI function call-
ing [14], LangChain tool calling [8], and the Model Context Protocol (MCP) from Anthropic [11]
provide various ways for agents to interact with a wide range of external resources. Among these
mechanisms, the most popular and widely adopted is MCP. With this protocol, developers can use
a consistent method to connect their agents to various data sources, tools, or workflows, helping
keep the overall design cleaner and more modular. Instead of tying tools directly to a particular
model, MCP lets various clients and models access the same set of resources. For instance, an agent

∗Xinyi Hou and Shenao Wang contributed equally to this work.

Authors’ Contact Information: Xinyi Hou, xinyihou@hust.edu.cn, Huazhong University of Science and Technology, Wuhan,
China; Shenao Wang, shenaowang@hust.edu.cn, Huazhong University of Science and Technology, Wuhan, China; Yifan
Zhang, zhangyifan95@hust.edu.cn, Huazhong University of Science and Technology, Wuhan, China; Ziluo Xue, xzl@hust.
edu.cn, Huazhong University of Science and Technology, Wuhan, China; Yanjie Zhao, yanjie_zhao@hust.edu.cn, Huazhong
University of Science and Technology, Wuhan, China; Cai fu, fucai@hust.edu.cn, Huazhong University of Science and
Technology, Wuhan, China; Haoyu Wang, haoyuwang@hust.edu.cn, Huazhong University of Science and Technology,
Wuhan, China.

, Vol. 1, No. 1, Article . Publication date: February 2026.

2

X Hou, S Wang, Y Zhang, Z Xue, Y Zhao, C Fu, and H Wang

can look up, choose, and use external tools simply by following a standard interface, without having
to worry about the underlying details. Because of these advantages, protocols like MCP are now
playing a key role in the open and interoperable agent ecosystems.

However, as MCP and similar open protocols are adopted more widely, new security and privacy
concerns have emerged [6]. Attackers have more opportunities to target not just individual models,
but the entire system, including users and external resources [1, 12]. Some of the risks that have
come up include unauthorized access, poor session management, manipulation of tool metadata,
and different types of injection attacks, such as command or prompt injection. These issues can
show up at any stage of the protocol’s operation. For example, attackers might take advantage
of user input or documents to influence what an agent does, or they could compromise an MCP
server to run harmful code or gain access to sensitive information [5, 15, 25, 28, 30, 32, 33].

So far, most research on MCP security has looked at where attacks might happen and what risks
exist in the broader ecosystem. For example, existing work has examined issues like tool poisoning,
prompt injection, and privilege escalation across servers. Some researchers have put together attack
taxonomies and developed detection tools, such as MindGuard [26], MCPLIB [4], and MCPTox [24].
On the agent side, the community has tried out different ways to reduce risk at the agent or
tool level, which include tracking agent behavior (AgentArmor [23]), using contract-based rules
(AgentSpec [21]), controlling privileges (SAGA [20]), and isolating inputs and outputs (DRIFT [9]).
Recent frameworks like A2AS [13] discuss runtime security controls for agentic systems, and the
latest standard [12] outlines general agent interconnection architectures. However, there is still
no dedicated protocol-level security enhancement specifically designed for MCP. Most existing
solutions are either built for individual agents or applications, or they only address specific threats.
Key challenges such as unified identity management, continuous security context tracking, and
end-to-end policy enforcement remain largely unaddressed.

Motivated by these challenges, we introduce the Secure Model Context Protocol (SMCP). SMCP
is designed as a practical security framework that makes open agent-tool environments more trust-
worthy, better controlled, and easier to audit from end to end. SMCP builds on the foundation of
MCP, extending it with a unified digital identity and trust infrastructure, robust mutual authentica-
tion, continuous security context propagation, fine-grained policy enforcement, and comprehensive
audit logging. By embedding these features directly into the protocol, SMCP addresses a wide
range of security risks seen in modern agentic workflows, all while preserving interoperability and
flexibility for developers. This paper makes several key contributions:

• We analyze the main security risks in agent ecosystems built around MCP, tracing threats

throughout the protocol’s workflow and probing their underlying causes.

• We present the detailed architecture of SMCP as a security-enhanced extension to MCP,
explaining how it brings together identity management, session authentication, security
context propagation, policy enforcement, and audit logging into a unified protocol layer to
enable consistent and robust security across agent-tool interactions.

• We demonstrate the effectiveness of SMCP’s built-in mechanisms in mitigating major security
risks, using practical examples and systematically mapping specific threat types to the
corresponding SMCP controls and enforcement strategies.

The remainder of the paper is structured as follows. § 2 reviews the background of LLM-powered
autonomous agents and the MCP. § 3 systematically analyzes the security risks in MCP workflows.
§ 4 introduces the design and mechanisms of SMCP. § 5 presents practical use cases and risk
mitigation mappings. § 6 reviews the work related to MCP security and agentic system protection.
§ 7 discusses the development roadmap and future directions. Finally, § 8 concludes the paper.

, Vol. 1, No. 1, Article . Publication date: February 2026.

SMCP: Secure Model Context Protocol

3

2 Background

2.1 LLM Powered Autonomous Agents
Autonomous agents powered by LLMs are an emerging direction in intelligent systems. Instead of
relying solely on single-turn conversations, these agents place LLMs at the center and combine
them with modules for planning, memory, and tool use (see Figure 1) [3, 10]. This allows agents to
understand their surroundings, make decisions, and take actions in more complex situations [28].
As a result, LLMs can now take on long-term tasks and interact with their environment in a more
active way. Specifically, the planning module breaks down user goals into specific steps, often using
strategies such as chain-of-thought reasoning or self-reflection. The memory module keeps track
of both recent context and longer-term knowledge, helping the agent plan ahead and learn from
experience. The tools module lets the agent reach out to external resources for tasks like searching
for information, running calculations, or executing code, which greatly extends what the LLM can
do. Finally, the execution module decides when to use these tools or take other actions based on
the plan, and it sends any new results back to memory so the agent can keep improving over time.

Fig. 1. Overview of a Typical LLM-based Autonomous Agent Architecture.

2.2 Model Context Model (MCP)
Before the emergence of the MCP protocol, LLM agents primarily relied on a variety of non-
unified approaches when interacting with external tools, as shown in Table 1. While these methods
were typically sufficient for small-scale, single-task scenarios, they faced significant scalability
bottlenecks when required to simultaneously access a large number of heterogeneous data sources
and tools or to share capabilities across multiple models and applications.

As LLM agents have grown more complex and the number of available tools has increased, it has
become much harder to describe, manage, and connect these resources in a way that is both scalable
and independent of any single implementation. To address these issues, Anthropic introduced the
Model Context Protocol (MCP) at the end of 2024 [11]. Drawing inspiration from general-purpose
protocols like the Language Server Protocol (LSP), MCP is designed as a single, flexible interface
for accessing external tools and shared context.

As shown in Figure 2, the architecture of MCP consists of three core components: the MCP host,
MCP client, and MCP server [6]. The MCP host is the environment where LLMs are deployed and
where the task context is kept. For example, this could be a desktop assistant or an intelligent
development environment. The MCP client operates within the host and serves as a bridge between
the LLMs and external resources. It is responsible for starting requests, understanding user intent,

, Vol. 1, No. 1, Article . Publication date: February 2026.

AgentToolsPlanningActionMemoryShort-termmemoryLong-termmemoryReflectionChain-of-ThoughtsTree-of-ThoughtsWebBrowser( )FileManager( )DatabaseQuery( )EmailSender( )…more…moreContext RetrievalExperience AccessTool Results4

X Hou, S Wang, Y Zhang, Z Xue, Y Zhao, C Fu, and H Wang

Table 1. Comparison of LLM Tool Integration Paradigms.

Paradigm

Main Features

Limitations

Manual API Integration

Developers directly connect external APIs, offering
maximum flexibility for customized scenarios.

Implementation is complex, maintenance
costs are high, and scalability is limited.

Standard Plugin

Agent Framework

RAG + Vector DB

Plugins are discovered and invoked through standard-
ized interfaces such as OpenAPI, simplifying integra-
tion within one platform.

The approach is typically stateless, re-
stricted to a single platform, and difficult
to reuse across different environments.

Tools are abstracted and orchestrated within an agent
framework (e.g., LangChain), supporting dynamic se-
lection and workflow management by the LLM.

Integration is highly dependent on specific
frameworks, resulting in weak interoper-
ability and limited extensibility.

Retrieval-augmented generation enables LLMs to in-
corporate external knowledge via vector search, en-
hancing context understanding.

This method is limited to information re-
trieval and does not support action execu-
tion or data modification.

Protocol-based (MCP)

A unified and extensible protocol enables decoupled,
dynamic discovery and invocation of tools and re-
sources across applications and models.

The protocol ecosystem is still evolving,
and consistency and security best practices
are not yet fully established.

managing responses, and coordinating the process of using external tools. The MCP server, which
is on the service side, offers three types of capabilities for LLMs: tools, resources, and prompts.
The tools module wraps external APIs or operational logic, so the client can call these tools and
receive results. The resources module manages various data sources, such as databases, files, or
cloud storage. The prompts module provides reusable workflow templates that help make tool use
more efficient and keep interactions consistent.

Fig. 2. The Workflow of MCP (Reproduced from Our Previous Work [6]).

The complete MCP workflow is as follows: when a user sends a request, the MCP host interprets
what kind of action is required and then the MCP clientcontacts the MCP server through a standard
communication layer. The server replies with a list of available tools and capabilities that fit the
current context. The host picks the right tool, makes the necessary API call, and, once the task is
finished, returns the results to the user. This process, while ensuring generality, also retains the
ability for dynamic configuration, bidirectional interaction, and multi-task scheduling, providing
fundamental protocol support for building more flexible, secure, and scalable agent systems.

, Vol. 1, No. 1, Article . Publication date: February 2026.

MCP ClientsPrompt:“Can you please fetch the latest stock price of AAPL and notify me via email?”MCP ServersCapabilitiesToolsResourcesPrompts②InitialResponse③Notification①InitialRequestTransferLayerDataSourceWeb ServicesDatabaseLocalFilesTool SelectionAPI InvocationIntentAnalysisNotificationSamplingOrchestrationUserMCP Workflow(ChatApps,IDEs,···,AI Agents)MCPHosts1:1ClientServerSMCP: Secure Model Context Protocol

5

3 Security Risks of MCP
The openness and flexibility that MCP offers for integrating AI agents and external tools also
introduce a wide range of security and privacy risks. As illustrated in Figure 3, threats may appear
throughout the entire MCP workflow, and each stage can present its own set of vulnerabilities
that attackers might exploit [1, 5, 30, 32]. These risks may come from various sources, including
outside attackers, malicious or compromised developers, supply chain participants, or insiders
with elevated access [6]. Attackers are usually interested in gaining unauthorized access, stealing
data, influencing agent behavior, or compromising the protocol’s integrity. Each part of the MCP
ecosystem, such as the host, client, server, and connected tools, may become a target for attacks.

Fig. 3. Security Threats and Attack Surfaces in MCP Workflow.

In our analysis, we examine the end-to-end workflow and consider possible risks at each stage.
Early steps in the process may be affected by weak authentication or poor session management,
while later phases may be exposed to tool poisoning, prompt injection, fake installers, or remote
code execution. Other threats, such as stolen credentials, privilege escalation, leaked tokens, and
misconfigurations, can also occur as the workflow progresses. In many cases, attackers may combine
several risks to increase the overall impact. Table 2 summarizes the main types of risk and how
they can appear in different stages of the workflow. Since our work is not focused on providing
an exhaustive list of all possible threats, we do not discuss each type in detail. Instead, our main
concern is the protocol’s design and the enforcement mechanisms that can help reduce these risks.

, Vol. 1, No. 1, Article . Publication date: February 2026.

LLM/Agent (MCP Host)LLM/Agent (MCP Host)MCP ClientMCP ClientMCP ServerMCP ServerTool Service/ResourceTool Service/Resource1. Establish connectionUnauthenticated AccessSession Management Flaws2. Request tool list3. Sync tool listNamespace TyposquattingTool Name ConﬂictTool PoisoningCommand InjectionRug PullsCross-Server Shadowing4. Provide tool list info5. Analyze task and tool requirementsPrompt InjectionIndirect Prompt Injection6. Select tool & send task infoInstaller SpooﬁngPreference Manipulation7. Forward tool invocation with task infoRemote Code ExecutionSQL Injection8. Invoke toolCredential TheftSandbox EscapeTool Chaining AbuseUnauthorized AccessPrivilege Abuse9. Return tool execution resultPath TraversalResource Content Poisoning10. Return tool invocation resultToken PassthroughCross-Tenant Data Exposure11. Return tool invocation resultVulnerable VersionsPrivilege PersistenceConﬁguration Drift6

X Hou, S Wang, Y Zhang, Z Xue, Y Zhao, C Fu, and H Wang

Table 2. Summary of Security Risks Across MCP Workflow Steps (Refined from our previous work [6]).

Step Risk Name

Risk Source

Risk Description

Unauthenticated Access

Protocol/Design Flaw

Session Management Flaws Protocol/Design Flaw

Namespace Typosquatting Malicious Developer

Tool Name Conflict

Malicious Developer

Tool Poisoning

Malicious Developer

Command Injection

External Attacker

Rug Pulls

Malicious Developer

Cross-Server Shadowing

Malicious Developer

Prompt Injection

User/Context Injection

Indirect Prompt Injection

External Attacker

Installer Spoofing

External Attacker

Preference Manipulation

Malicious Developer

Remote Code Execution

External Attacker

SQL Injection

External Attacker

Credential Theft

Insider/Privilege Abuse

Sandbox Escape

User/Context Injection

Tool Chaining Abuse

User/Context Injection

Unauthorized Access

Insider/Privilege Abuse

Privilege Abuse

Insider/Privilege Abuse

Path Traversal

External Attacker

Resource Content Poisoning External Attacker

1

3

5

6

7

8

9

Token Passthrough

Protocol/Design Flaw

10

Cross-Tenant Data Exposure Insider/Privilege Abuse

Lack of robust authentication allows attackers to impersonate
clients or servers, leading to unauthorized access and potential
data leakage.
Weak session handling enables hijacking, replay attacks, or
persistent unauthorized access by failing to securely generate,
expire, or revoke sessions.

Attackers register servers with deceptively similar names to
legitimate ones, tricking users or agents and facilitating supply
chain compromise.
Ambiguous or conflicting tool names enable attackers to sub-
stitute malicious tools for legitimate ones during selection.
Malicious logic or hidden instructions are embedded in tool
metadata, causing agents to execute unintended or harmful
operations.
Insecure parameter handling allows attackers to inject system
commands, leading to arbitrary code execution on the server.
Initially benign servers or tools are later updated to include
malicious payloads, betraying established trust.
Attackers exploit overlapping tool definitions to cause agents
to invoke attacker-controlled tools instead of trusted ones.

Malicious user prompts manipulate the model’s reasoning, trig-
gering unintended actions or privilege escalation.
Adversarial instructions are embedded in external data sources,
covertly influencing model behavior or leaking data.

Attackers distribute tampered installer packages or auto-
installers, introducing malware or backdoors during tool setup.
Persuasive or deceptive tool descriptions bias agent or model
selection, steering preference toward attacker-controlled tools.

Insufficient input validation allows attacker-supplied data to
trigger arbitrary code execution on the server.
Unsanitized parameters are passed into database queries, en-
abling manipulation or exfiltration of backend data.

Attackers extract API keys, tokens, or credentials from the
execution environment for long-term unauthorized access.
Malicious tools escape isolation, gaining access to host system
resources or enabling lateral movement.
Multiple low-risk tools are chained to perform unintended
high-impact operations, evading policy checks.
Insufficient access control allows invocation of tools or re-
sources beyond intended permissions.
Over-permissioned tools or misconfigured policies enable per-
sistent unauthorized operations or escalation.

Improper path handling allows attackers to access or overwrite
arbitrary files via crafted return data.
Manipulated output data injects malicious content, misleading
downstream agents or corrupting workflows.

Sensitive tokens or credentials are inadvertently forwarded
along the workflow, exposing them to unauthorized parties.
In multi-tenant environments, improper segregation leads to
leakage of data between tenants or sessions.

Vulnerable Versions

Version/Config Management Outdated or unpatched tool/server versions remain in use, ex-

posing the system to known exploits.

11

Privilege Persistence

Version/Config Management Revoked or outdated credentials are not invalidated after up-

Configuration Drift

Version/Config Management Manual or uncoordinated configuration changes accumulate,

causing deviation from the intended security baseline.

dates, allowing retention of unauthorized access.

, Vol. 1, No. 1, Article . Publication date: February 2026.

SMCP: Secure Model Context Protocol

7

4 Secure Model Context Protocol (SMCP)
As stated before, the security threats in open agent-tool ecosystems are deeply rooted in the lack
of unified trust, fragmented authentication, and limited auditability throughout the workflow.
Addressing such systemic challenges requires a holistic, protocol-level solution that can guarantee
the authenticity of all participants, enforce strong mutual authentication, maintain a con-
tinuous security context across all operations, and ensure comprehensive accountability.
SMCP is designed to meet these needs. It serves as a unified security framework that combines
identity management, session authentication, security context tracking, policy enforcement, and
audit logging. At the core of this approach, the Trusted Component Registry makes sure that only
verified and traceable participants are allowed in agent-tool interactions. Each connection is created
using mutual authentication, and every operation is linked to a security context that contains
details about identity, delegation, and risk. The system enforces detailed access policies to support
minimal privilege and flexible protection. Complete audit logs are kept so that all important actions
can be followed from start to finish. As shown in Figure 4, SMCP brings these key elements together
to provide strong access control, protection during operation, and clear accountability. This allows
multiple agents to work together securely and reliably, while still keeping the system compatible
and flexible.

Fig. 4. SMCP: Secure Model Context Protocol.

4.1 Trusted Component Registry
4.1.1 Unified Digital Identity and Trust Infrastructure. SMCP is built on a unified digital identity
and trust infrastructure that spans multiple systems and trust domains, which forms the foundation
for protocol operation. Unlike solutions that only address a single type of entity, such as agents,
SMCP brings together all key participants in the ecosystem. This includes not only human users
and organizational accounts, but also different types of agents, tools, and external resource services
such as MCP servers, model services, and dataset services. It also covers governance components
like identity and policy services, bringing them all under a common identity and trust framework.
This design covers not only the structured encoding and account management of all entity types,
but also a comprehensive Trusted Component Registry and standardized assertion mechanisms: only

, Vol. 1, No. 1, Article . Publication date: February 2026.

MCP ClientsPrompt:“Can you please fetch the latest stock price of AAPL and notify me via email?”MCP Servers②InitialResponse③Notification①InitialRequestTransferLayerDataSourceWeb ServicesDatabaseLocalFiles(ChatApps, IDEs,···, AI Agents)MCPHostsClientServerTrusted Component RegistryUser-RegistryHost-RegistrySecurity ContextIdentity CodeDelegation ChainPolicyRisk LevelPolicyAuditLogAuthenticationCall ChainagentId, taskId, sessionIdauthnAssertionId, toolId,delegatorChain,riskLevel,  …actionCode, result, timestamp,signature,auditRef,…User•Unified identity allocation•Credential management•Policy issuance and auditServer-RegistryResource-Registry§4.1§4.2§4.4§4.3§4.58

X Hou, S Wang, Y Zhang, Z Xue, Y Zhao, C Fu, and H Wang

those components registered and bound to the unified identity namespace via digital credentials
are recognized as trusted components eligible to participate in the SMCP invocation plane.

4.1.2

Scope and Key Elements. The trust infrastructure of SMCP comprises three interrelated parts:

• Structured identity codes for all principal types;
• Identity accounts and digital credential managed by the Trusted Component Registry;
• Standardized authentication assertions and pre-access verification processes.

These components provide a consistent trust anchor throughout the operation of SMCP, supporting
session establishment, capability access, and call-chain auditing. Table 3 summarizes the major
entity types and key attributes managed within this infrastructure.

Table 3. Entity Types and Key Attributes in the SMCP Trusted Component Registry

Registry Type

Example

Identity and Account

Credential and Trust Info

User

Human user, org ac-
count

Agent (MCP host) General/vertical

agent, orchestrator

Account mapped to a unique 32-character
identity code; stores basic profile, organiza-
tional relationships, and assigned roles in
the registry

Login secret, certificate, or verifi-
able credential; encodes user affili-
ation, role, authorization baseline,
and compliance attributes

Each MCP Host assigned a 32-character iden-
tity code; registry records code or model
hash, deployment environment, functional
scope, and operational boundaries

Host digital credential with public
key, declared capabilities, permis-
sion baseline, and optionally dele-
gation or controller information

MCP Server

Tool services, integra-
tion endpoint

Each server endpoint or instance issued
a unique identity code; registry maintains
provider/operator, exposed capability de-
scription, and service sensitivity level

Resource

Model API, dataset,
external service

Each resource assigned a unique modelId,
datasetId, etc.; registry stores owner, ver-
sion, provenance, and sensitivity labels

Service certificate or verifiable cre-
dential; includes service identity,
supported authentication, compli-
ance and data handling policy, and
operational trust attributes

Resource-level credential or asser-
tion issued by trust anchor; spec-
ifies compliance, permitted usage
scope, risk classification, and sup-
ports auditability

Structured Identity Code for All Entities. At the identification layer, SMCP defines unified
4.1.3
encoding rules and type fields for different entity categories.An example as shown in Figure 5. Every
discoverable, callable, or delegable entity is assigned a fixed-length, 32-character identity code
using the character set [0-9A-Z]. This applies to users, agents, tool services, models, and resource
endpoints. The code reserves type fields for distinguishing users (human or organizational), agents
(general or domain-specific), tools and resources (MCP servers, APIs, model/data services), and
governance/audit components (identity services, policy points, log aggregators, etc). Other fields
encode version, authority, registrant, registration year, package/account serial, instance serial, and
a checksum. This cross-type, parseable encoding enables global uniqueness, rapid validation (e.g.,
MOD 97-10 checksum), and binding of all protocol interactions to a stable identity namespace
without exposing internal implementation details.

Identity Lifecycle and Credential Management. SMCP defines a unified identity lifecycle
4.1.4
management framework atop the Trusted Component Registry, including registration, verifica-
tion, archival, credential issuance, and activation for each entity type. For agents, the sponsor or
developer submits a registration request with functional descriptions, system composition and
environment digests (e.g., code/model hashes, dependency fingerprints), behavioral boundaries,

, Vol. 1, No. 1, Article . Publication date: February 2026.

SMCP: Secure Model Context Protocol

9

Fig. 5. Example of SMCP Structured Identity Code.

and supporting documentation. The registration service evaluates risk and required evidence based
on task sensitivity and deployment context, verifies all proofs, then creates a registry entry, assigns
the identity code, and snapshots verified information as the baseline.

Likewise, users and organizations must complete registration and verification (potentially lever-
aging existing IAM/IDaaS infrastructure), incorporating account attributes, organizational relation-
ships, and baseline authorization into the unified identity domain. Tool and resource services must
register before being added to the capability directory or invoked by SMCP, disclosing provider/op-
erator, capability sensitivity, and compliance boundaries. Models and datasets must declare training
data sources, usage restrictions, and sensitivity tags. This creates a unified graph of users, agents,
tools, models, data, and organizations, enabling delegation chains, access control, and audit trails.
Once registered, independent credential issuance services generate digital credentials for each
entity in the form of public key certificates or verifiable credentials containing the identity code, type,
provider/delegator information, capability scope, privilege level, security/compliance attributes,
and public key reference. After issuance, the identity code and credential are returned for secure
storage and use. Only after this process is an entity’s digital identity considered active and eligible
for trusted participation in SMCP operations. To prevent “register-once, never-update” risks, SMCP
supports unified update, lock, and revocation mechanisms. When an agent’s implementation,
capability, or environment changes significantly, an identity update process is triggered (identity
code remains, registry/account info is updated, credentials may be rotated). Tool/resource services
follow similar flows for capability/sensitivity/operator changes. For misbehavior, credential leaks,
or delegator revocation, identity accounts may be locked or deactivated, with full audit trails
preserved for compliance and forensic review.

4.2 Session Establishment and Mutual Authentication
A secure session in SMCP is established through a process of mutual authentication between
entities, based on the unified digital identity and credential infrastructure provided by the Trusted
Component Registry. This approach ensures that both parties in a session can reliably verify each
other’s identities. Each session is then linked to a verifiable security context, which serves as the
basis for all secure interactions and the transfer of context information throughout the protocol.

4.2.1 Authentication and Mutual Verification. During cross-entity interactions, trust is established
not by request payloads alone, but via standardized authentication and assertion flows:

• When a subject initiates a request, the relying party evaluates its access control policy
to determine the required authentication strength (e.g., agent identity only, or additional
tool/model trust attributes).

• Upon challenge, the requester assembles an appropriate credential bundle, signs dynamic

challenges, and presents them (e.g., via mutual TLS or application-level assertions).

, Vol. 1, No. 1, Article . Publication date: February 2026.

1234567891011{"identityCode": "AG01AC01COMP2500012345005678X7A3","type": "AG", // AG=Agent, US=User, TL=Tool, MD=Model, IN=Infrastructure"version": "01", // Identity code version"authority": "AC01", // Identity authority code"registrant": "COMP", // Registrant/organization code"year": "25", // Registration year (2025)"packageSerial": "00012345", // Package/account serial number"instanceSerial": "005678", // Instance serial number"checksum": "X7A3"// Checksum (MOD 97-10)}10

X Hou, S Wang, Y Zhang, Z Xue, Y Zhao, C Fu, and H Wang

• The verifier (identity service or relying party) checks credential signatures, trust chains,
validity, revocation, and ensures scope matches the request. For delegation, registry records
are used to validate the full authorization chain from delegator to current actor.

• After verification, an authentication assertion is generated, including result, assurance level,
subject identity, delegator summary, unique ID, and timestamp. The relying party uses this
assertion and local policy to decide on access, privileges, further checks, or session setup.

With unified digital identity, a Trusted Component Registry, and trust infrastructure across all
entity types, SMCP ensures that all protocol-level identifiers (agentId, toolServiceId, modelId,
datasetId, etc.) can be traced to a registered, auditable trusted component. This provides a consis-
tent, measurable trust layer for all cross-boundary interactions.

Session Initialization and Security Context Binding. After mutual authentication is success-
4.2.2
fully completed, a dedicated session is established between the interacting entities. At this stage,
SMCP generates a session-specific security context that aggregates essential security semantics,
including the identities of both parties, the verified delegation chain, risk level, session identifiers,
and relevant metadata. This security context receives a unique identifier, such as sessionId or
callChainId, and is cryptographically bound to the session using the secure key material ne-
gotiated during authentication. The security context is explicitly associated with all subsequent
messages, task requests, and tool invocations within the session. This association ensures that
every operation can be traced back to the original authentication event and that context integrity is
maintained throughout the invocation chain. If the session is interrupted, expires, or is terminated,
the associated security context is invalidated to prevent unauthorized reuse. Through this mecha-
nism, all downstream operations inherit a consistent and auditable security baseline, supporting
end-to-end access control, policy enforcement, and auditability across the entire SMCP workflow.

4.3 Security Context
4.3.1 Definition and Design Principles. Building on digital identity and trust infrastructure, SMCP
defines a unified security context structure at the protocol abstraction layer and requires that this
context be explicitly carried by or be traceable from core interaction elements such as sessions,
tasks, messages, and tool invocations. The unified security context consolidates security semantics
that are scattered across different components and boundaries into a set of common fields, thus
providing a shared language at the protocol level for end-to-end authentication, authorization
control, and audit tracing. Table 4 presents the main fields of this security context.

This unified security context is not intended to replace the field definitions in existing standards.
Instead, it integrates with current structures in two ways. First, for existing session, task, and
message structures such as sessionId, taskId, and id in agent interaction standards, SMCP
attaches references or digests of the security context by extending metadata or security extension
fields. Second, for tool capability invocations and responses, SMCP separates the security context
into invocation metadata, which is transmitted together with the tool invocation payload. Through
this mechanism, whether for model-oriented context construction, resource-oriented capability
access, or long-chain invocations involving multiple components, all events can be represented as
occurring under a unified security context and endorsed by the Trusted Component Registry. This
approach provides a consistent security semantic foundation for subsequent access control, risk
management, and audit tracing.

4.3.2 Roles and Objects in SMCP. The runtime environment of SMCP involves four core roles:

, Vol. 1, No. 1, Article . Publication date: February 2026.

SMCP: Secure Model Context Protocol

11

Table 4. Unified Security Context Fields in SMCP.

Field

Example Name

Description

Session Identifier

sessionId

Call Chain Identifier

callChainId

Delegation Chain

delegatorChain

Caller Identity

callerAgentId

Peer Identity

peerId

Authentication Assertion

authnAssertionId

Risk Level

riskLevel

Policy Reference

policyRef

Data Sensitivity

dataSensitivity

Timestamp Protection

timestamp, nonce

A session ID shared across messages, tasks, and invocations, cor-
responding to the session concept in agent interaction standards.

A globally unique ID for a user task, used for end-to-end au-
ditability across agents and tools.

A summary of the authorization chain from user or organiza-
tion through the entry agent to the current actor, supporting
accountability and policy enforcement.

The identity code of the agent initiating the current request,
bound to the identity management domain and trusted compo-
nent registry.

The identity of the interaction peer (tool service, model, or data
service), used for mutual authentication and access control.

Reference to the most recent authentication assertion, used to
prove the current session or channel’s assurance level.

The risk classification for the current task or invocation (e.g.,
low, medium, high, critical), driving adaptive authentication and
authorization strategies.

A pointer to the applicable set of access control and compliance
policies, used for decision explanation and auditing.

The sensitivity level of data involved in this interaction, con-
straining access to the minimum necessary.

Used with underlying TLS or message signatures to resist replay
and ordering attacks.

• Invoking Agent: This includes both entry-point agents and downstream business agents.
These agents initiate capability invocations via the tool access component, with their identities
mapped to corresponding agentId and trust metadata within the SMCP identity system.
• Tool Service: This component connects to the tool catalog and runtime environment, is
responsible for receiving invocation requests, orchestrating specific tool instances, and
aggregating results. It is typically identified externally by a toolServiceId.

• Tool Instance: These are the operational units that perform actual actions within the resource

access domain, such as database queries, API calls, or local script executions.

• Policy Engine: This component works in conjunction with identity and authorization
services. It makes decisions on authorization, downgrade, or denial based on the security
context, tool security properties, and relevant component metadata.

Building on these roles, the protocol revolves around three main types of objects: Tool Capa-
bility Description, Tool Invocation Request, and Tool Execution Response, as illustrated
in Table 5. SMCP requires explicit embedding of security context fields (such as callChainId,
delegatorChain, riskLevel, etc.) within these objects, and associates them with the identity and
capability metadata of each component. This ensures that the complete invocation chain, from user
to agent to tool, maintains a consistent security semantic throughout.

Through these objects, SMCP brings the high-level security semantics down to the tool layer, so
that each invocation can be verified and audited in terms of who authorized it, the associated risk
level, and what capability and underlying components have been accessed.

, Vol. 1, No. 1, Article . Publication date: February 2026.

12

X Hou, S Wang, Y Zhang, Z Xue, Y Zhao, C Fu, and H Wang

Table 5. Core Objects and Their Roles in SMCP.

Object

Example Identifiers

Description

Tool Capability Description toolId, sensitivityLevel

Tool Invocation Request

toolCallId, callChainId

Tool Execution Response

actionCode, auditRef

Uniquely identifies the tool and its security attributes, used
for access control and risk assessment before invocation.

Binds a unified security context and component identity
references, enabling each invocation to be traced back to
upstream sessions, tasks, and underlying components.

Returns the execution status and result summary, and pro-
vides audit record references for the resource access domain
and related components.

Security Extensions for Tool Capabilities. Building upon existing tool capability descriptions
4.3.3
(such as name, input/output patterns, invocation quotas, etc.), SMCP introduces a set of security
attributes for each tool to drive authorization decisions and invocation downgrade strategies. Table 6
presents an illustrative set of such fields. Figure 6 is an example of a tool capability description
with the security extension fields included alongside the standard capability metadata:

Table 6. Security Extension Fields for Tool Capabilities (Illustrative).

Field

Example Name

Description

Sensitivity Level

sensitivityLevel

Minimum Identity Assurance minIdentityAssurance

Allowed Delegators

allowedDelegators

Data Policy

dataPolicy

Audit Requirement

auditRequirement

Categorizes tools into public, internal, sensitive, or highly
sensitive levels, each corresponding to different invocation
constraints.

Requires the invoker to have at least a certain authentica-
tion strength (can be mapped to LoA or custom levels in
this framework).

Specifies which subject types or tenants may access the
tool via agent delegation (e.g., only users from the same
organization are allowed).

Indicates whether results may be stored long-term, included
in agent long-term memory, used for model retraining, or
require redaction; can be linked to compliance labels of
underlying resources.

Specifies the minimum granularity for invocation chain
records (e.g., whether to record parameter summaries, result
summaries, and caller context).

Tool services can fetch and cache such security capability descriptions when loading tool catalogs.
Subsequently, each time an SMCP tool invocation request is received, the tool service matches the
security context in the invocation message with these fields, thereby achieving access control and
risk evaluation in a unified semantic framework.

Security Semantics of SMCP Invocation and Response. SMCP treats a tool invocation as a
4.3.4
controlled capability access request, issued by an agent on behalf of an upstream subject, within
a specific delegation chain and risk configuration. Table 7 summarizes the key security fields in
SMCP invocation and response messages.

During the invocation phase, the agent constructs an SMCP tool invocation request based on
the security context formed in the current session, binding task semantics with tool capabilities,

, Vol. 1, No. 1, Article . Publication date: February 2026.

SMCP: Secure Model Context Protocol

13

Fig. 6. SMCP Tool Capability.

Table 7. Key Security Fields in SMCP Invocation and Response.

Direction

Field

Description

Invocation Request

agentId,
authnAssertionId

delegatorChain,
riskLevel,
dataSensitivity

callChainId,
sessionId, taskId,
toolCallId

Specifies the invoking agent’s identity and the current identity assurance
status, which can be jointly verified with the tool’s minIdentityAssurance
requirement.

Propagates the delegation chain and risk semantics from upstream sessions
to the tool layer, serving as the basis for authorization and downgrade
decisions.

Binds the current tool invocation to the global invocation chain, session, and
specific task, forming a traceable invocation segment that can be correlated
with tool-side audit records.

toolId, toolVersion,
toolInput

Describes the capability and parameters compatible with existing tool
interfaces to drive the actual execution.

actionCode, result

Indicates the execution status and result data (or summary), compatible
with existing invocation patterns.

Tool Response

timestamp,
signature

auditRef

Timestamp and integrity protection information signed by the tool service
or security gateway, ensuring result non-repudiation.

Reference to the tool-side local audit record, which can be associated with
callChainId and related component identifiers for end-to-end traceability.

security constraints, and component identities. Upon completing the execution of a specific tool
instance, the tool service returns the result and relevant security metadata to the invoking agent
through an SMCP tool execution response message.

4.4 Policy Enforcement and Least-Privilege Control
SMCP leverages the unified security context and capability model to support fine-grained policy
enforcement and the principle of least privilege throughout the tool invocation lifecycle. Every
invocation request is evaluated by the policy engine, which makes decisions based on attributes
such as agent identity, delegator chain, risk level, data sensitivity, and permitted operations.

, Vol. 1, No. 1, Article . Publication date: February 2026.

12345678910111213141516171819{"type": "SMCP.ToolCapability","toolId": "TOOL-SALES-QUERY-001","version": "2025.3","displayName": "Sales Aggregated Metrics Query","description": "Query aggregated sales metrics for a given time range and region.","io": {"inputSchemaRef": "schema://tools/sales-query/input-v1","outputSchemaRef": "schema://tools/sales-query/output-v1"},"security": {"sensitivityLevel": "internal","minIdentityAssurance": "aal2","allowedDelegators": [{"subjectType": "user","allowedOrgIds": ["ORG-ACME"],"allowedRoles": ["data_analyst", "sales_analyst"]      },      {        "subjectType": "agent",        "allowedAgentIds": ["AGENT-REPORT-ENTRY-0001"]      }    ],    "dataPolicy": {      "allowLongTermStorage": true,      "allowIntoAgentLongTermMemory": false,      "allowForModelTraining": false,      "requiresRedaction": false    },    "auditRequirement": {      "recordParamsSummary": true,      "recordResultSummary": true,      "recordCallerContext": true,      "minRetentionDays": 365    }  }}20212223242526272829303132333435363738394014

X Hou, S Wang, Y Zhang, Z Xue, Y Zhao, C Fu, and H Wang

4.4.1 End-to-End Policy Enforcement Workflow. As shown in Figure 7, SMCP policy enforcement
is tightly integrated into the end-to-end tool invocation workflow:

Fig. 7. Sequence Diagram of Secure Agent ↔ Tool Interoperability in SMCP.

(1) Capability Discovery: The caller agent initiates by retrieving tool capability descriptions,
which include both functional and security-relevant metadata (such as sensitivity level,
allowed delegators, and identity assurance thresholds).

(2) Invocation Request Construction: The agent constructs a tool invocation request, embed-
ding the comprehensive security context (e.g., callChainId, delegatorChain, riskLevel,
dataSensitivity, and identity fields).

(3) Policy Evaluation: Upon receiving the request, the tool service forwards the relevant

security context and tool capability information to the policy engine.

(4) Decision Making: The policy engine evaluates the request against configured authorization
policies, considering both the runtime security context and the static properties of the tool.
It returns a decision of PERMIT, DENY, or PERMIT WITH OBLIGATIONS (such as masking,
aggregation, or rate limits).

(5) Enforcement and Obligation Application: If permitted, the tool service executes the
tool call, applying any obligations imposed by the policy engine. If denied, a detailed denial
response is returned, including an audit reference.

, Vol. 1, No. 1, Article . Publication date: February 2026.

Caller AgentCaller AgentTool ServiceTool ServicePolicy EnginePolicy EngineSensitive ResourceSensitive ResourcegetToolCapabilities(toolId)ToolCapabilities(toolId, sensitivityLevel,minIdentityAssurance, allowedDelegators, ...)SACP.ToolCallRequest(toolCallId, agentId, toolId,securityContext, toolInput)EvaluatePolicy(requestContext,securityContext, toolCapability)Decision(PERMIT / DENY /PERMIT WITH OBLIGATIONS)alt== DENYSACP.ToolCallResponse(actionCode="DENY",reason, auditRef)== PERMIT or PERMIT_WITH_OBLIGATIONSResourceRequest(toolId, toolInput,securityLabels)ResourceResponse(rawResult)applyObligations(masking/aggregation/limits)createAuditRecord(auditRef, callChainId)SACP.ToolCallResponse(actionCode="SUCCESS"/"DOWNGRADED",resultSummary, appliedSecurity, auditRef, signature)SMCP: Secure Model Context Protocol

15

(6) Audit and Response: All actions, including policy decisions and applied obligations, are
logged with references to the security context for subsequent auditing. The agent receives
the response, which includes both result data and the relevant security and audit metadata.
This sequence ensures that every tool invocation is subject to dynamic, context-aware policy
evaluation, and that the minimum required permissions are strictly enforced at each step. The
explicit embedding of audit references and security outcomes in the response messages further
supports traceability and compliance.

4.4.2 Policy Evaluation Mechanisms and Enforcement Architecture. The policy enforcement archi-
tecture of SMCP is fundamentally anchored in the propagation of an explicit, structured security
context with every invocation across the protocol chain. Within this framework, the policy en-
gine acts as the Policy Decision Point (PDP), while agents and tool services function as Policy
Enforcement Points (PEPs). This separation of roles enables a modular and auditable security model,
ensuring that policy enforcement remains consistent and traceable across diverse deployment
environments. Unlike traditional static access control, SMCP evaluates each tool invocation dy-
namically based on the complete security context. This context includes the full delegation chain,
risk level, data sensitivity, and the identity and trust level of every participant in the call chain.
The policy language enables fine-grained constraints on any of these attributes; for instance, a
policy can permit access to a sensitive function only if the risk level is below “medium” and the
delegation chain contains a verified human. Beyond simple allow or deny outcomes, policies may
impose obligations such as result masking, rate limiting, or requiring additional verification steps,
all tightly bound to context attributes. Every decision and enforcement action is linked to unique
identifiers in the context, supporting end-to-end traceability and compliance.

Fig. 8. Example of SMCP Tool Invocation Request. This includes delegation chain, risk level, data sensitivity,
and capability constraints, which are evaluated by the policy engine to determine access and obligations.

Figure 8 illustrates a typical SMCP tool invocation request. Key fields such as delegatorChain,
riskLevel, and dataSensitivity provide the basis for policy decisions by the engine, which

, Vol. 1, No. 1, Article . Publication date: February 2026.

"policyRef": "POLICY-ORG-ACME-REPORTING-USER"},"tool": {"toolId": "TOOL-SALES-QUERY-001","toolVersion": "2025.3","capabilityRef": "capability:sales_aggregated_metrics","requestedSensitivityLevel": "internal","requestedScopes": ["sales_reporting"],"minIdentityAssurance": "aal2"},"toolInput": {"timeRange": "2025-Q3","region": ["NA"],"metrics": ["revenue", "orders", "churn_rate"],"groupBy": ["month"],"filters": {"excludeTestAccounts": true}},”constraints": {"maxExecutionTimeMs": 5000,"maxRows": 5000,"allowPartialResult": true}}123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657{"type": "SMCP.ToolCallRequest","toolCallId": "TC-2025-12-19-000123","timestamp": "2025-12-19T10:17:05Z","caller": {"agentId": "AGENT-REPORT-ENTRY-0001","agentType": "entry_agent"},"securityContext": {"sessionId": "S-7F3K9L2M8Q1Z4X6C0D5B8N2R4T6Y8W1","taskId": "T-2025-12-19-000089","callChainId": "CC-2025-12-19-00004567","authnAssertionId": "AA-9Z2X7C4V1B6N3M8Q5","delegatorChain": [{"subjectId": "U-ORG-ACME-00123","subjectType": "user","role": "data_analyst"},{"subjectId": "AGENT-REPORT-ENTRY-0001","subjectType": "agent","role": "entry_agent"}],"riskLevel": "medium","dataSensitivity": "internal",16

X Hou, S Wang, Y Zhang, Z Xue, Y Zhao, C Fu, and H Wang

determines whether the action is permitted, downgraded, or denied. The agentId and toolId
fields associate the invocation with specific agent and tool entities, supporting both access control
and audit requirements. In this example, the policy engine can enforce that only requests with an
appropriate risk level and an allowed delegation chain are processed, and may require masking or
other obligations if the data sensitivity demands it.

Once the policy engine reaches a decision, the tool service must enforce the result, including
any specified obligations. As shown in Figure 9, the tool execution response records the applied
security policy, data handling status, and audit information. The appliedSecurity field specifies
the sensitivity level and data policy that were enforced, while auditRef and signature ensure
the result’s authenticity and end-to-end traceability. This structured response allows downstream
systems and auditors to verify compliance with organizational and regulatory policies.

Fig. 9. Example of SMCP Tool Execution Response. The response details the applied security policy, actual
data handling, and provides audit and signature fields to enable end-to-end traceability and compliance.

Through this context-driven, fine-grained policy evaluation, SMCP enforces the principle of least
privilege: at every invocation, only the minimal necessary permissions and capabilities are granted,
and these are dynamically adjusted as context changes, ensuring robust and adaptive security.

4.5 Audit Logging and Traceability
Comprehensive audit logging is a cornerstone of SMCP’s security and compliance framework. Every
critical protocol operation, including agent authentication, capability negotiation, policy evaluation,
tool invocation, and response delivery, is systematically captured in the audit log with structured
and high-fidelity metadata. Rather than serving as a passive record, the audit log is designed to
actively support retrospective security analysis, such as detecting misconfigurations or abuse, as
well as demonstrating compliance with regulatory or organizational policies. A distinctive feature of
SMCP audit logging is its close integration with the security context that is propagated throughout
each protocol interaction. Each log entry is bound to unique identifiers such as callChainId
and auditRef, precise timestamps, digital signatures, and a complete contextual snapshot of the

, Vol. 1, No. 1, Article . Publication date: February 2026.

12345678910111213141516171819202122232425262728293031323334353637383940414243444546474849{  "type": "SMCP.ToolCallResponse",  "toolCallId": "TC-2025-12-19-000123",  "timestamp": "2025-12-19T10:17:06Z",  "status": {    "actionCode": "SUCCESS",    "errorCode": null,    "errorMessage": null,    "partial": false  },  "result": {    "summary": "North America sales in 2025-Q3 increased by 12.4% QoQ.",    "detailsRef": "blob://results/sales-report/2025-Q3/NA/summary-v1",    "metrics": [      {        "month": "2025-07",        "revenue": 1250000,        "orders": 18450      },      {        "month": "2025-08",        "revenue": 1325000,        "orders": 19120     },{"month": "2025-09","revenue": 1398000,"orders": 19980}]},"appliedSecurity": {"appliedSensitivityLevel": "internal","appliedDataPolicy": "DATA-POLICY-ACME-AGG-ONLY","redactedFields": [],"requiresStepUpForNext": false},"audit": {"auditRef": "AUDIT-TOOL-SALES-2025-12-19-10-17-06-0001","signature": "sig-base64-...","signedBy": "TOOL-SALES-SERVICE","signedAt": "2025-12-19T10:17:06Z","hashAlgo": "SHA-256"}}SMCP: Secure Model Context Protocol

17

operation. This approach ensures comprehensive, end-to-end traceability and guarantees non-
repudiation for every action within the system.

As summarized in Table 8, the audit log captures a broad range of key attributes, including the
identities of all actors and subjects, detailed operation metadata, policy decisions and obligations,
sensitivity and risk levels, result summaries, and cryptographic proofs of integrity. This compre-
hensive coverage enables the audit log to support real-time monitoring, automated risk detection,
and post-incident forensic analysis, forming the foundation for both proactive and retrospective
security controls.

Table 8. Key Attributes Captured in SMCP Audit Log Entries.

Attribute Category

Example Fields

Description

Timestamps

timestamp, signedAt

Records the time of invocation, response, and log entry signing,
supporting chronological reconstruction and non-repudiation.

Actor and Subject Identities

Operation Details

agentId, userId,
delegatorChain, subjectId,
subjectType, role

Identifies the primary invoker, end user, and any delegation chain;
distinguishes between user and agent roles for accountability and
compliance tracking.

toolId, capabilityRef,
actionCode, taskId, sessionId,
callChainId, auditRef

Describes the invoked tool, requested capability, action performed,
and unique identifiers for the session, task, and audit chain, enabling
granular traceability and correlation.

Policy Decisions and Obligations

policyRef, policyDecision,
obligations, constraints

Captures the applicable policy references, decisions (e.g., permit
with obligations), imposed constraints, and obligations such as data
masking or aggregation.

Sensitivity and Risk Level

requestedSensitivityLevel,
appliedSensitivityLevel

Indicates the sensitivity and risk classification requested and actually
applied to the data, supporting risk-aware auditing and compliance.

Result Metadata

resultSummary, metrics,
resultDetailsRef

Summarizes the outcome of the operation, including key perfor-
mance indicators and references to detailed result data.

Signatures and Integrity

signature, hashAlg, signedBy

Provides cryptographic signatures, hash algorithms, and signer iden-
tity to ensure log integrity and enable tamper evidence.

An example of a structured audit log entry is shown in Figure 10, which demonstrates how these
attributes are organized in practice. Each entry can be cross-referenced with both the originating
request and the resulting response, ensuring a complete and verifiable chain of custody for sensitive
operations. By mandating explicit, structured, and tamper-evident audit records for all security-
relevant events, SMCP provides trustworthy and contextually justified decision-making in both
automated and human-in-the-loop agentic workflows.

5 SMCP Use Cases
To illustrate the practical application and security features of the SMCP, we present a representative
use case that demonstrates its complete workflow. This example describes how the main mechanisms
of SMCP, including secure authentication, policy enforcement, capability-based access control, and
audit logging, cooperate to address security challenges in a modular software system.

As outlined in Table 9, the process begins with the user and tools performing mutual authentica-
tion through the SMCP authentication module. This initial verification ensures that only trusted
participants are allowed to proceed. Following authentication, the user searches for available
tools by querying the centralized registry. The registry applies strict naming policies and verifies
metadata, which helps to prevent issues such as typosquatting and the registration of unauthorized
or potentially malicious tools. Once a suitable tool is identified, the user submits a request to
invoke the tool. Before the request is processed, the SMCP policy engine evaluates it according
to predefined security and capability policies. This step ensures that unauthorized or unsafe op-
erations are blocked before execution. During invocation, each tool operates within a restricted

, Vol. 1, No. 1, Article . Publication date: February 2026.

18

X Hou, S Wang, Y Zhang, Z Xue, Y Zhao, C Fu, and H Wang

Fig. 10. Example of a Structured Audit Log Entry in SMCP.

security context determined by SMCP, thereby minimizing privilege exposure and limiting access
to sensitive resources.

Table 9. Mapping of Security Risks to SMCP Mitigation Steps.

Risk Type

SMCP

Mitigation Details

Unauthenticated Access

§ 4.2

Session Management Flaws § 4.2

Namespace Typosquatting

§ 4.1

Tool Name Conflict

§ 4.1

Enforces strong mutual authentication and secure exchange of credentials
to prevent unauthorized entities from accessing any part of the system.

Secures session initiation, renewal, and termination to prevent session hi-
jacking and unauthorized reuse. Ensures active session validation through-
out the workflow.

Trusted registry enforces strict naming policies and validation, blocking
deceptively named or malicious components from being registered or dis-
covered.

Registry ensures tool identifier uniqueness with conflict checks and pre-
vents ambiguity or accidental invocation of the wrong tool.

Tool Poisoning

§ 4.1, § 4.4 Only verified tools are registered; policy engine validates tool metadata
and enforces behavior checks before invocation, reducing risk of malicious
tool insertion.

Command Injection

§ 4.4

Policy rules and input validation filter unsafe payloads, preventing mali-
cious command execution in tool calls or actions.

(Continued)

, Vol. 1, No. 1, Article . Publication date: February 2026.

1234567891011121314151617181920212223242526272829303132333435363738394041424344454647484950"riskLevel": "medium","dataSensitivity": "internal","policyDecision": {"effect": "PERMIT_WITH_OBLIGATIONS","obligations": ["aggregation", "redactPII"],"constraints": {"maxExecutionTimeMs": 5000,"maxRows": 5000,"allowPartialResult": true}},"resultSummary": "North America sales in 2025-Q3 increased by 12.4% QoQ.","resultDetailsRef": "bbi://results/sales-report/2025-Q3/NA/summary-v1","metrics": [{"month": "2025-07", "revenue": 1250000, "orders": 18450},{"month": "2025-08", "revenue": 1325000, "orders": 19120},{"month": "2025-09", "revenue": 1398000, "orders": 19980}],"signedAt": "2025-12-19T10:17:06Z","signedBy": "TOOL-SALES-SERVICE","signature": "sig-base64-encoded-example","hashAlgo": "SHA-256"}{"type": "SMCP.AuditLogEntry","auditRef": "AUDIT-TOOL-SALES-2025-12-19T10-17-06-0001","timestamp": "2025-12-19T10:17:06Z","callChainId": "CC-2025-12-19-0004567","sessionId": "7F3K9LM2B0I4ZXG6B0SD8BN2R4T6Y8W1","taskId": "T-2025-12-19-000089","agentId": "AGENT-REPORT-ENTRY-0001","userId": "U-ORG-ACME-00123","delegatorChain": [{"subjectId": "U-ORG-ACME-00123","subjectType": "user","role": "data_analyst"},{"subjectId": "AGENT-REPORT-ENTRY-0001","subjectType": "agent","role": "entry_agent"}],"toolId": "TOOL-SALES-QUERY-001","capabilityRef": "sales_aggregated_metrics","actionCode": "SUCCESS","policyRef": "POLICY-ORG-ACME-REPORTING-USER","requestedSensitivityLevel": "internal","appliedSensitivityLevel": "internal",SMCP: Secure Model Context Protocol

19

Risk Type

Rug Pulls

Table 9. Continued.

SMCP

Mitigation Details

§ 4.1

Registry maintains version history and provenance for all tool entries,
preventing undetected malicious updates or sudden removals.

Cross-Server Shadowing

§ 4.1

Centralized registry ensures authoritative mapping and prevents registra-
tion of duplicate or shadow tool endpoints.

Prompt Injection

§ 4.3, § 4.4 Security context constrains available agent actions and policy checks ensure
prompt contents cannot escalate privileges or induce undesired behaviors.

Indirect Prompt Injection

§ 4.3, § 4.4 Policy checks and secure context propagation restrict the impact of adver-

Installer Spoofing

§ 4.1

Preference Manipulation

§ 4.1

Remote Code Execution

§ 4.4

SQL Injection

§ 4.4

sarial manipulation in indirect or multi-stage prompts.

Authenticated, integrity-checked distribution of installers and updates
blocks use of tampered or fake installation sources.

Registry verifies tool descriptions and metadata are signed and authentic,
protecting against attacker-influenced preference modifications.

All inputs are validated and policy controls restrict code execution scope,
minimizing the risk from untrusted or injected code.

Policy engine includes input validation for data operations, effectively
blocking injection attacks in tool or server interactions.

Credential Theft

§ 4.3, § 4.4 Security context traces credential use; least-privilege access design and

Sandbox Escape

Tool Chaining Abuse

Unauthorized Access

§ 4.4

§ 4.4

§ 4.4

scoping minimize possible credential exposure or misuse.

Policy and runtime isolation controls restrict the execution environment
of tools, limiting their ability to break out of sandboxes.

Capability models and policy logic limit tool chaining depth and validate
all chained calls to prevent escalation or abuse.

Fine-grained policy and capability enforcement ensure no component re-
ceives excess permissions, reducing attack surface.

Privilege Abuse

§ 4.4, § 4.5 Policy restricts privilege escalation; audit logs provide full traceability and

enable detection of abnormal privilege use.

Path Traversal

§ 4.4

Policy checks enforce strict path validation for all resource accesses, block-
ing unauthorized or dangerous file operations.

Resource Content Poisoning § 4.4, § 4.5 Policy validation and comprehensive audit logging enable early detection

of manipulated or malicious resource results.

Token Passthrough

§ 4.3, § 4.5 Scoped context design restricts token propagation; audit logs detect and

alert on any inadvertent credential forwarding.

Cross-Tenant Data Exposure § 4.3, § 4.5 Security context enforces strict tenant isolation; audit logs track and sup-

port investigation of any data leakage events.

Vulnerable Versions

§ 4.1, § 4.5 Registry enforces component version control; audit logs help identify out-

dated or unpatched components for timely updates.

Privilege Persistence

§ 4.5

Audit trail tracks every privilege modification, supporting detection and
remediation of improper retention or persistence of access.

Configuration Drift

§ 4.1, § 4.5 Registry maintains a reference configuration baseline; auditing reveals

unauthorized or accidental configuration changes.

, Vol. 1, No. 1, Article . Publication date: February 2026.

20

X Hou, S Wang, Y Zhang, Z Xue, Y Zhao, C Fu, and H Wang

6 Related Work

6.1 MCP Security
Since the release of the MCP, the security community has rapidly moved to identify potential
vulnerabilities inherent in its open and modular design. Early efforts have focused on cataloging
risks and establishing benchmarks for attack surfaces. Adversa.ai released a comprehensive
list of the top 25 MCP vulnerabilities, highlighting issues ranging from unauthorized access to
supply chain risks [1]. Meanwhile, academic researchers have sought to formalize these risks
within the protocol’s architecture. Hou et al. provided a comprehensive landscape analysis of MCP,
detailing security threats and future research directions [6]. In parallel, Guo et al. conducted a
systematic analysis of MCP security, introducing MCPLib to categorize threats across the client-
host-server interaction model [4]. Building on these foundational taxonomies, recent work has
exposed specific attack vectors arising from the trust agents place in external servers. Zhao et al.
treated servers as active threat actors, identifying twelve distinct attack categories where malicious
implementations can exploit host-LLM interactions [34]. Specific vulnerabilities in the registration
phase were highlighted by Wang et al. via MCPTox, which demonstrated how tool poisoning can
embed malicious instructions in metadata to manipulate agent behavior [24]. Beyond direct attacks,
the complexity of toolchains introduces indirect risks; Zhao et al. revealed parasitic toolchain
attacks, where passive data sources inject prompts to hijack execution flows without direct user
interaction [32]. Furthermore, Wang et al. uncovered economic threats through MPMA, showing
how servers can manipulate descriptions to bias LLM selection for financial gain [25]. In response to
these threats, the community has moved towards empirical assessment and defensive frameworks.
Hasan et al. conducted a large-scale empirical study of open-source MCP servers, finding that despite
high community engagement, many servers suffer from maintainability issues and vulnerabilities
like credential exposure [5]. To enable proactive security, Radosevich and Halloran developed
McpSafetyScanner, an agentic tool for auditing servers against exploits such as remote access
control before deployment [16]. On the benchmarking front, Yang et al. introduced MCPSecBench
to systematically evaluate 17 attack types across the protocol’s layers, exposing weaknesses in
current host defenses [30]. Finally, Shi et al. proposed SecMCP, a defense mechanism that leverages
latent polytope analysis to detect conversation drift, effectively identifying adversarial deviations
in agent trajectories [17].

6.2 Agentic AI System Security
Parallel to protocol-specific research, the broader field of agentic AI security has developed various
defense mechanisms focusing on the agent’s runtime environment and decision-making processes.
Comprehensive surveys by Gan et al. [2] and Li et al. [10] have categorized threats facing LLM-
based agents, emphasizing the need for robust defenses against prompt injection and unsafe action
execution. To mitigate these risks, researchers have moved beyond static rules towards dynamic
runtime protection. AgentArmor utilizes program analysis to trace agent behavior [23], while
AgentSpec enforces formal contracts to prevent deviations [21]. Advancing this dynamic capability,
Xiang et al. proposed GuardAgent, which employs a dedicated agent to interpret safety requests
and generate executable guardrail code via knowledge-enabled reasoning, ensuring compliance
without altering the target agent’s core logic [29]. Shifting from reactive to proactive defense,
Wang et al. introduced PRO2GUARD, a framework that leverages discrete-time Markov chains to
probabilistically predict unsafe agent trajectories, enabling interventions before violations actually
occur [22]. In the domain of interaction integrity and access control, recent works have focused on
granular policy enforcement. Jing et al. developed the Model Contextual Integrity Protocol (MCIP),
which integrates a guardian model and tracking tools to enforce information flow integrity based on

, Vol. 1, No. 1, Article . Publication date: February 2026.

SMCP: Secure Model Context Protocol

21

a fine-grained risk taxonomy [7]. Complementing this, Shi et al. presented Progent, a programmable
privilege control framework that enforces the principle of least privilege by intercepting tool calls
with deterministic security policies, effectively reducing the attack surface for coding and web
agents [18]. These approaches sit alongside architectures like SAGA [20] and isolation techniques
such as DRIFT [9] and A2AS [13], creating a multi-layered defense landscape.

7 SMCP Roadmap
The SMCP is being developed as an open and extensible security foundation, providing unified
digital identity, contextual access control, and end-to-end auditability for agent-tool interactions.
NEAR TERM, the goal is to integrate SMCP’s core security mechanisms, such as trusted compo-
nent registries, structured digital identity codes, and unified security context propagation, into
existing MCP implementations and widely-used agent frameworks. This stage will focus on devel-
oping reference implementations, facilitating compatibility with current agent architectures, and
demonstrating feasibility in real-world engineering deployments. Additional research will target
best practices for entity registration workflows, authentication procedures, and security context
message formats.
MID TERM, the focus will shift to expanding SMCP’s policy enforcement and runtime auditing
capabilities. Key directions include developing fine-grained risk-adaptive access control engines,
scalable audit logging infrastructure, and advanced delegation and revocation management. Industry
feedback and empirical studies will inform improvements in policy expressiveness, compliance
automation, and operational efficiency. This phase will also explore interoperability with other
agent security standards and protocols.
LONG TERM, the roadmap envisions SMCP as a foundational layer for secure, interoperable agent
ecosystems across diverse domains and trust boundaries. Future work will include supporting
multi-domain federation, automated trust negotiation, and integration with evolving AI-native
protocols and governance frameworks. Ultimately, the goal is to establish SMCP as a reference
standard for secure agent interconnection and collaborative AI governance, enabling scalable,
accountable, and trustworthy agentic AI on a global scale.

8 Conclusion
This paper presented the SMCP, a comprehensive security framework designed to address the
unique challenges of open, MCP-based agent ecosystems. We systematically analyzed the security
risks inherent in the MCP workflow, which arise from the protocol’s open and composable archi-
tecture. While existing research has made significant progress in attack analysis and agent-level
defenses, there remains a critical gap in protocol-native, end-to-end security enhancements for
MCP systems. SMCP fills this gap by introducing unified digital identity and trust infrastructure,
mutual authentication, continuous security context propagation, fine-grained policy enforcement,
and structured audit logging directly at the protocol layer. Through these mechanisms, SMCP de-
livers robust access control, adaptive runtime protection, and comprehensive accountability across
agent-tool interactions. Our analysis and use cases demonstrate that SMCP can effectively mitigate
the most pressing security threats in modern agentic workflows while maintaining flexibility and
interoperability. Looking ahead, the SMCP roadmap envisions its integration into mainstream
agent architectures and standardization as a foundational layer for secure, scalable, and trustworthy
agentic AI ecosystems.

References
[1] Adversa.ai. 2025. MCP Security Top 25 Vulnerabilities. https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/.

, Vol. 1, No. 1, Article . Publication date: February 2026.

22

X Hou, S Wang, Y Zhang, Z Xue, Y Zhao, C Fu, and H Wang

[2] Wensheng Gan, Shicheng Wan, and Philip S. Yu. 2023. Model-as-a-Service (MaaS): A Survey. In IEEE International
Conference on Big Data, BigData 2023, Sorrento, Italy, December 15-18, 2023, Jingrui He, Themis Palpanas, Xiaohua
Hu, Alfredo Cuzzocrea, Dejing Dou, Dominik Slezak, Wei Wang, Aleksandra Gruca, Jerry Chun-Wei Lin, and Rakesh
Agrawal (Eds.). IEEE, 4636–4645. doi:10.1109/BIGDATA59044.2023.10386351

[3] Yuyou Gan, Yong Yang, Zhe Ma, Ping He, Rui Zeng, Yiming Wang, Qingming Li, Chunyi Zhou, Songze Li, Ting Wang,
Yunjun Gao, Yingcai Wu, and Shouling Ji. 2024. Navigating the Risks: A Survey of Security, Privacy, and Ethics Threats
in LLM-Based Agents. CoRR abs/2411.09523 (2024). arXiv:2411.09523 doi:10.48550/ARXIV.2411.09523

[4] Yongjian Guo, Puzhuo Liu, Wanlun Ma, Zehang Deng, Xiaogang Zhu, Peng Di, Xi Xiao, and Sheng Wen. 2025.

Systematic Analysis of MCP Security. arXiv:2508.12538 [cs.CR] https://arxiv.org/abs/2508.12538

[5] Mohammed Mehedi Hasan, Hao Li, Emad Fallahzadeh, Gopi Krishnan Rajbahadur, Bram Adams, and Ahmed E. Hassan.
2025. Model Context Protocol (MCP) at First Glance: Studying the Security and Maintainability of MCP Servers. CoRR
abs/2506.13538 (2025). arXiv:2506.13538 doi:10.48550/ARXIV.2506.13538

[6] Xinyi Hou, Yanjie Zhao, Shenao Wang, and Haoyu Wang. 2025. Model Context Protocol (MCP): Landscape, Security

Threats, and Future Research Directions. arXiv:2503.23278 [cs.CR] https://arxiv.org/abs/2503.23278

[7] Huihao Jing, Haoran Li, Wenbin Hu, Qi Hu, Xu Heli, Tianshu Chu, Peizhao Hu, and Yangqiu Song. 2025. MCIP:
Protecting MCP Safety via Model Contextual Integrity Protocol. In Proceedings of the 2025 Conference on Empirical
Methods in Natural Language Processing, Christos Christodoulopoulos, Tanmoy Chakraborty, Carolyn Rose, and Violet
Peng (Eds.). Association for Computational Linguistics, Suzhou, China, 1177–1194. doi:10.18653/v1/2025.emnlp-main.62
[8] LangChain. 2022. LangChain: Framework for developing applications powered by language models. https://github.

com/langchain-ai/langchain.

[9] Hao Li, Xiaogeng Liu, Hung-Chun Chiu, Dianqi Li, Ning Zhang, and Chaowei Xiao. 2025. DRIFT: Dynamic Rule-Based
Defense with Injection Isolation for Securing LLM Agents. arXiv:2506.12104 [cs.CR] https://arxiv.org/abs/2506.12104
[10] Yuanchun Li, Hao Wen, Weijun Wang, Xiangyu Li, Yizhen Yuan, Guohong Liu, Jiacheng Liu, Wenxing Xu, Xiang
Wang, Yi Sun, Rui Kong, Yile Wang, Hanfei Geng, Jian Luan, Xuefeng Jin, Zilong Ye, Guanjing Xiong, Fan Zhang,
Xiang Li, Mengwei Xu, Zhijun Li, Peng Li, Yang Liu, Ya-Qin Zhang, and Yunxin Liu. 2024. Personal LLM Agents:
Insights and Survey about the Capability, Efficiency and Security. CoRR abs/2401.05459 (2024). arXiv:2401.05459
doi:10.48550/ARXIV.2401.05459

[11] Model Context Protocol. 2024. What is the Model Context Protocol (MCP)? https://modelcontextprotocol.io/docs/

getting-started/intro. Accessed: 2025-12-16.

[12] National Technical Committee for Information Technology Standardization and Artificial Intelligence Subcom-
mittee, National Technical Committee for Information Technology Standardization. 2025. Artificial Intelli-
gence — Agent Interconnection — Part 1: General Architecture. https://std.samr.gov.cn/gb/search/gbDetailed?id=
3BAB0AA8A7FC31E3E06397BE0A0AA43F.

[13] Eugene Neelou, Ivan Novikov, Max Moroz, Om Narayan, Tiffany Saade, Mika Ayenson, Ilya Kabanov, Jen Ozmen,
Edward Lee, Vineeth Sai Narajala, Emmanuel Guilherme Junior, Ken Huang, Huseyin Gulsin, Jason Ross, Marat
Vyshegorodtsev, Adelin Travers, Idan Habler, and Rahul Jadav. 2025. A2AS: Agentic AI Runtime Security and Self-
Defense. arXiv:2510.13825 [cs.CR] https://arxiv.org/abs/2510.13825

[14] OpenAI. 2023. Function calling. https://platform.openai.com/docs/guides/function-calling.
[15] Brandon Radosevich and John Halloran. 2025. MCP Safety Audit: LLMs with the Model Context Protocol Allow Major

Security Exploits. CoRR abs/2504.03767 (2025). arXiv:2504.03767 doi:10.48550/ARXIV.2504.03767

[16] Brandon Radosevich and John Halloran. 2025. MCP Safety Audit: LLMs with the Model Context Protocol Allow Major

Security Exploits. arXiv:2504.03767 [cs.CR] https://arxiv.org/abs/2504.03767

[17] Haoran Shi, Hongwei Yao, Shuo Shao, Shaopeng Jiao, Ziqi Peng, Zhan Qin, and Cong Wang. 2025. Quantifying

Conversation Drift in MCP via Latent Polytope. arXiv:2508.06418 [cs.CL] https://arxiv.org/abs/2508.06418

[18] Tianneng Shi, Jingxuan He, Zhun Wang, Hongwei Li, Linyu Wu, Wenbo Guo, and Dawn Song. 2025. Progent:

Programmable Privilege Control for LLM Agents. arXiv:2504.11703 [cs.CR] https://arxiv.org/abs/2504.11703

[19] Noah Shinn, Shunyu Labash, et al. 2023. Reflexion: an Autonomous Agent with Dynamic Memory and Self-Reflection.

arXiv preprint arXiv:2303.11366 (2023). https://arxiv.org/abs/2303.11366

[20] Georgios Syros, Anshuman Suri, Jacob Ginesin, Cristina Nita-Rotaru, and Alina Oprea. 2025. SAGA: A Security

Architecture for Governing AI Agentic Systems. arXiv:2504.21034 [cs.CR] https://arxiv.org/abs/2504.21034

[21] Haoyu Wang, Christopher M. Poskitt, and Jun Sun. 2025. AgentSpec: Customizable Runtime Enforcement for Safe and

Reliable LLM Agents. arXiv:2503.18666 [cs.AI] https://arxiv.org/abs/2503.18666

[22] Haoyu Wang, Christopher M. Poskitt, Jun Sun, and Jiali Wei. 2026. Pro2Guard: Proactive Runtime Enforcement of
LLM Agent Safety via Probabilistic Model Checking. arXiv:2508.00500 [cs.AI] https://arxiv.org/abs/2508.00500
[23] Peiran Wang, Yang Liu, Yunfei Lu, Yifeng Cai, Hongbo Chen, Qingyou Yang, Jie Zhang, Jue Hong, and Ye Wu.
2025. AgentArmor: Enforcing Program Analysis on Agent Runtime Trace to Defend Against Prompt Injection.
arXiv:2508.01249 [cs.CR] https://arxiv.org/abs/2508.01249

, Vol. 1, No. 1, Article . Publication date: February 2026.

SMCP: Secure Model Context Protocol

23

[24] Zhiqiang Wang, Yichao Gao, Yanting Wang, Suyuan Liu, Haifeng Sun, Haoran Cheng, Guanquan Shi, Haohua
Du, and Xiangyang Li. 2025. MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers.
arXiv:2508.14925 [cs.CR] https://arxiv.org/abs/2508.14925

[25] Zihan Wang, Hongwei Li, Rui Zhang, Yu Liu, Wenbo Jiang, Wenshu Fan, Qingchuan Zhao, and Guowen Xu. 2025.
MPMA: Preference Manipulation Attack Against Model Context Protocol. CoRR abs/2505.11154 (2025). arXiv:2505.11154
doi:10.48550/ARXIV.2505.11154

[26] Zhiqiang Wang, Junyang Zhang, Guanquan Shi, HaoRan Cheng, Yunhao Yao, Kaiwen Guo, Haohua Du, and Xiang-Yang
Li. 2025. MindGuard: Tracking, Detecting, and Attributing MCP Tool Poisoning Attack via Decision Dependence
Graph. arXiv:2508.20412 [cs.CR] https://arxiv.org/abs/2508.20412

[27] Jason Wei, Xuezhi Wang, Dale Schuurmans, Maarten Bosma, Brian Ichter, Fei Xia, Ed H. Chi, Quoc V. Le, and Denny
Zhou. 2022. Chain-of-Thought Prompting Elicits Reasoning in Large Language Models. Advances in Neural Information
Processing Systems 35 (2022), 24824–24837. arXiv:2201.11903 https://arxiv.org/abs/2201.11903

[28] Lilian Weng. 2023. LLM-powered Autonomous Agents. lilianweng.github.io (June 2023). https://lilianweng.github.io/

posts/2023-06-23-agent/

[29] Zhen Xiang, Linzhi Zheng, Yanjie Li, Junyuan Hong, Qinbin Li, Han Xie, Jiawei Zhang, Zidi Xiong, Chulin Xie, Carl
Yang, Dawn Song, and Bo Li. 2025. GuardAgent: Safeguard LLM Agents by a Guard Agent via Knowledge-Enabled
Reasoning. arXiv:2406.09187 [cs.LG] https://arxiv.org/abs/2406.09187

[30] Yixuan Yang, Daoyuan Wu, and Yufan Chen. 2025. MCPSecBench: A Systematic Security Benchmark and Playground
for Testing Model Context Protocols. CoRR abs/2508.13220 (2025). arXiv:2508.13220 doi:10.48550/ARXIV.2508.13220
[31] Shunyu Yao, Dian Yu, Jeffrey Zhao, Izhak Shafran, Tom Griffiths, Graham Neubig, and Yuan Cao. 2023. Tree of
Thoughts: Deliberate Problem Solving with Large Language Models. arXiv preprint arXiv:2305.10601 (2023). https:
//arxiv.org/abs/2305.10601

[32] Shuli Zhao, Qinsheng Hou, Zihan Zhan, Yanhao Wang, Yuchong Xie, Yu Guo, Libo Chen, Shenghong Li, and Zhi
Xue. 2025. Mind Your Server: A Systematic Study of Parasitic Toolchain Attacks on the MCP Ecosystem. CoRR
abs/2509.06572 (2025). arXiv:2509.06572 doi:10.48550/ARXIV.2509.06572

[33] Weibo Zhao, Jiahao Liu, Bonan Ruan, Shaofei Li, and Zhenkai Liang. 2025. When MCP Servers Attack: Taxonomy,

Feasibility, and Mitigation. CoRR abs/2509.24272 (2025). arXiv:2509.24272 doi:10.48550/ARXIV.2509.24272

[34] Weibo Zhao, Jiahao Liu, Bonan Ruan, Shaofei Li, and Zhenkai Liang. 2025. When MCP Servers Attack: Taxonomy,

Feasibility, and Mitigation. arXiv:2509.24272 [cs.CR] https://arxiv.org/abs/2509.24272

, Vol. 1, No. 1, Article . Publication date: February 2026.

