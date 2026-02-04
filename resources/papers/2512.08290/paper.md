Systematization of Knowledge: Security and Safety
in the Model Context Protocol Ecosystem

Shiva Gaire∗, Srijan Gyawali∗, Saroj Mishra∗, Suman Niroula∗, Dilip Thakur∗, and Umesh Yadav∗
Tribhuvan University: mail@shivagaire.com.np, gyawalisrijan01@gmail.com
University of North Dakota: saroj.mishra773@gmail.com
Youngstown State University: sum.nir1@gmail.com
University of Missouri: dileepthakur87@gmail.com
University of Toledo: yadav.umesh0518@gmail.com

5
2
0
2

c
e
D
3
1

]

R
C
.
s
c
[

2
v
0
9
2
8
0
.
2
1
5
2
:
v
i
X
r
a

Abstract— The Model Context Protocol (MCP) has emerged
as the de facto standard for connecting Large Language Models
(LLMs) to external data and tools, effectively functioning as the
”USB-C for Agentic AI.” While this decoupling of context and
execution solves critical interoperability challenges, it introduces
a profound new threat landscape, where the boundary between
epistemic errors (hallucinations) and security breaches (unau-
thorized actions) dissolves. This Systematization of Knowledge
(SoK) aims to provide a comprehensive taxonomy of risks in
the MCP ecosystem, distinguishing between adversarial security
threats (e.g.,
tool poisoning) and
epistemic safety hazards (e.g., alignment failures in distributed
tool delegation). We analyze the structural vulnerabilities of
MCP primitives, specifically Resources, Prompts, and Tools, and
demonstrate how ”context” can be weaponized to trigger unau-
thorized operations in multi-agent environments. Furthermore,
we survey state-of-the-art defenses, ranging from cryptographic
provenance (ETDI) to runtime intent verification, and conclude
with a roadmap for securing the transition from conversational
chatbots to autonomous agentic operating systems.

indirect prompt

injection,

Index Terms—Model Context Protocol, Agentic AI, LLM
Security, AI Safety, Indirect Prompt Injection, Tool Poisoning,
Systematization of Knowledge (SoK), Zero Trust Architecture.

I. INTRODUCTION

A. Background and Motivation

The field of Artificial Intelligence is undergoing a paradig-
matic shift from Conversational AI—where models generate
text in isolation—to Agentic AI, where models perceive, rea-
son, and act upon the external world. This transition requires
a standardized connective tissue to link probabilistic Large
Language Models (LLMs) with deterministic digital systems.
The Model Context Protocol (MCP), introduced in late 2024,
has emerged as this standard, effectively serving as the “USB-
C for AI applications” by abstracting the complexities of data
retrieval and tool execution into a unified open protocol [1],
[2].

The adoption of MCP solves a critical interoperability bot-
tleneck, famously known as the “M ×N integration problem,”
allowing any model to connect to any data source without
bespoke adapters [3]. However, this architectural decoupling
introduces profound security implications. By standardizing
the interface between an LLM and local files, databases, and

∗All authors contributed equally to this work.

remote APIs, MCP significantly expands the attack surface
of AI systems. It transforms the LLM from a passive text
processor into an active system component with shell-level
privileges, capable of executing actions based on potentially
untrusted context.

As MCP adoption accelerates

in enterprise environ-
ments—powering IDEs, data pipelines, and customer sup-
port agents—the industry faces a critical knowledge gap.
While individual vulnerabilities like prompt
injection are
well-documented, there is no comprehensive framework un-
derstanding how these threats manifest in a decentralized,
protocol-driven ecosystem where control flow is determined
by semantic context rather than code.

B. Problem Statement: Security vs. Safety in MCP

The core challenge in securing MCP ecosystems lies in the
convergence of security and safety failures. In traditional soft-
ware, these domains are distinct: security protects against ma-
licious adversaries (e.g., SQL injection), while safety protects
against unintended system behaviors (e.g., race conditions). In
MCP, this distinction blurs.

A “security” breach, such as an attacker injecting a mali-
cious document into a company’s knowledge base (Indirect
Prompt Injection), can trigger a “safety” failure, where the
model honestly but mistakenly believes it is authorized to
delete a database. Conversely, a safety failure, such as model
hallucination regarding a tool’s parameters, can lead to a
security breach where sensitive data is exfiltrated to a public
log [4].

Current defense mechanisms are ill-equipped for this du-
ality. Traditional firewalls cannot inspect the semantic intent
of a JSON-RPC message, and LLM safety filters cannot
see the downstream consequences of a tool execution. This
paper argues that securing MCP requires a unified threat
model that treats context availability and execution privilege
as inextricably linked variables.

C. Scope of the Survey

This Systematization of Knowledge (SoK) focuses on the
unique risks introduced by the Model Context Protocol
ecosystem. Our analysis encompasses:

A. Evolution of Context Protocols in AI Systems

The integration of external context into AI systems has
evolved through three distinct phases. Initially, developers
relied on bespoke glue code and static context injection, where
retrieval logic was hard-coded into the application layer. This
unscalable approach led to the “M × N integration problem,”
where every model provider (M ) required custom connectors
for every data source (N ) [3].

The second phase introduced proprietary plugin ecosystems
(e.g., OpenAI Plugins), which standardized tool definitions
locked developers into specific model vendors. MCP
but
represents the third phase: a universal open standard that op-
erates over local and remote transports (Stdio, SSE), allowing
any model to connect to any server without vendor-specific
adapters [9].

B. MCP Architecture and Design Principles

• Protocol Primitives: Vulnerabilities inherent in the de-
sign of Resources, Prompts, and Tools as defined in the
MCP specification [1].

• Topology Risks: Threats arising from the distributed na-
ture of Host-Client-Server interactions, including supply
chain risks in open tool registries.

• Intersection of Threats: We specifically exclude general
LLM adversarial attacks (e.g., weight poisoning) unless
they directly impact the protocol’s integrity or execution
flow.

D. Contributions of this Paper

To our knowledge,

this is the first academic survey to
systematize the risks of the Model Context Protocol. Our
contributions are as follows:

1) Unified Vulnerability Taxonomy: We propose a novel
taxonomy (Table III) that distinguishes between Adver-
sarial Security Threats (e.g., tool masquerading, context
poisoning) and Epistemic Safety Hazards (e.g., alignment
failures in tool delegation).

2) Structural Analysis of MCP Primitives: We analyze
how the decoupling of ”Context” (Resources) and ”Ac-
tion” (Tools) creates new classes of vulnerabilities, such
as Cross-Primitive Escalation, where read-only access is
weaponized to trigger write-actions [5].

3) Survey of Emerging Defenses: We synthesize state-of-
the-art mitigation strategies, moving beyond basic prompt
engineering to architectural solutions like the Enhanced
Tool Definition Interface (ETDI) [6] and kernel-level
session isolation [7].

4) Forensic Case Studies: We reconstruct real-world in-
cidents, such as the Supabase data leak [8], to derive
actionable lessons for enterprise deployment.

E. Organization of the Paper

The remainder of this paper is organized as follows: Section
II provides a technical overview of the MCP architecture.
Section III defines the threat landscape and adversarial actors.
Sections IV and V detail the specific security and safety chal-
lenges, respectively. Section VI surveys mitigation strategies
and architectural defenses. Section VII outlines open research
directions, and Section VIII presents case studies of recent
MCP-related incidents. Finally, Section IX concludes with a
roadmap for secure adoption.

II. OVERVIEW OF THE MODEL CONTEXT PROTOCOL
(MCP)

The Model Context Protocol (MCP) establishes a standard-
ized open protocol that decouples AI models from their data
sources and tools. By abstracting these connections into a
client-host-server topology, MCP aims to solve the interop-
erability challenges inherent in connecting Large Language
Models (LLMs) to local and remote ecosystems [1].

Fig. 1. MCP Architecture. The host application acts as the security boundary,
mediating interactions between the Model Interface and the external MCP
Server [1].

The architecture is founded on a Client-Host-Server model
designed to run locally or remotely. The design prioritizes
security boundaries by ensuring the LLM never connects

Host App ication (Security Boundary)Transport (Stdio / SSE)Mode  InterfaceMCP C ientMCP Serverdirectly to a data source; instead, all interactions are mediated
by the host application [1].

Key design principles include:
• Transport Agnosticism: The protocol runs over standard
input/output (Stdio) for local process isolation or Server-
Sent Events (SSE) for remote connections.

• Capability Negotiation: Connections begin with a hand-
shake where Client and Server declare their supported
features (e.g., resources, logging, prompts) before ex-
changing data.

• JSON-RPC 2.0: The message format relies on a state-
less, lightweight remote procedure call standard, ensuring
compatibility across programming languages [1].

C. Core Components and Data Flow

3) Clients and Applications: The “MCP Client” is the
protocol implementation embedded within the host applica-
tion. While the Host manages the user interface and process
lifecycle, the Client handles the strict protocol mechanics:
maintaining the connection, routing messages, and handling
error states. The Client acts as an aggregator, capable of
connecting to multiple Servers simultaneously and presenting
a unified list of tools to the Application layer. This aggregation
enables the “bring your own tools” paradigm central to MCP
[3].

4) Governance and Policy Layers: Governance is enforced
at the protocol edge via the capabilities handshake and runtime
permissions. Unlike web APIs where authentication is often
handled via headers, MCP relies on process-based access
control. The host application serves as the policy enforcement
point, intercepting tool execution requests (e.g., “Delete File”)
and requiring user or policy approval before passing the
command to the Server. Current research suggests this Human-
in-the-Loop (HITL) mechanism is the primary (and often
single) line of defense against agentic risks [4], [6].

D. Comparison with Traditional Protocol Ecosystems

MCP differs from traditional middleware like REST or

gRPC by embedding semantic intent into the connection.

Fig. 2. MCP Data Flow. The sequence demonstrates how a Model Interface
request is routed through the Client, approved by the Host Policy check, and
executed by the Context Source.

1) Model Interfaces: The “Model Interface” in MCP is
the abstraction layer managed by the host application (e.g.,
Claude Desktop, IDEs). It is responsible for the sampling
loop: sending the conversation history to the LLM, parsing
the LLM’s output for tool call requests, and serializing those
requests into MCP-compliant JSON-RPC messages. Crucially,
this interface creates a buffer between the probabilistic nature
of the model and the deterministic nature of the protocol,
ensuring that model hallucinations do not directly corrupt the
protocol state [9].

2) Context Sources and Connectors: In the MCP ecosys-
tem, context sources are encapsulated as “MCP Servers.”
These servers act as connectors that expose data via two
primary primitives:

• Resources: Passive data streams (identified by URIs
like file:///logs/error.txt) that the model can
read. These function similarly to GET requests in REST
but include subscription capabilities for real-time updates.
• Prompts: Server-defined templates that pre-package re-
sources and instructions. These allow connectors to define
“best practice” workflows (e.g., a “Git Commit” prompt
that automatically grabs the diff and asks for a message)
[1].

Fig. 3. Comparison of Control Flow. Traditional REST APIs (left) rely on
stateless, developer-driven requests. MCP (right) relies on stateful, intent-
driven sessions where the model determines execution paths.

TABLE I
COMPARISON OF MCP VS. TRADITIONAL PROTOCOLS

REST / OpenAPI

Model Context Protocol

Feature

Topology

Discovery

Stateless
quest/Response
Static Schema (Swagger)

Re-

Control Flow
Security

Client-Driven
Endpoint Authentication

Session

Stateful
(Stdio/SSE)
Dynamic Capability Ne-
gotiation
Model-Intent Driven
Host-mediated
Isolation

Process

While REST APIs are designed for deterministic developer
interactions, MCP is optimized for non-deterministic model

MCP ServerMCP ClientModel InterfaceMCP ServerMCP ClientModel InterfaceModel decides to use a toolHost performs Policy/Approval CheckModel processes new contextTool Call Request (JSON-RPC)Execute Tool RequestTool Execution Result (Data)Return Contextual DataMode  Context Protoco  (MCP)Traditiona  RESTMCP C ientMode  Interface (LLM)MCP ServerAPI Gateway / ServiceDeve oper C ientState ess RequestResponse DataStatefu  SessionTransportinteractions, where the “caller” (the LLM) determines the
execution path based on context [3].

E. Role of MCP in AI Integration and Multi-Agent Systems

MCP serves as the interoperability layer for Agentic AI.
By standardizing the tool interface, it solves the fragmenta-
tion problem in Multi-Agent Systems (MAS). In an MCP-
enabled MAS, agents can query the capabilities of other agents
(exposed as Servers) and hand off tasks dynamically. For
example, a “Coder Agent” can connect to a “Database Agent”
via MCP to inspect a schema, treating the Database Agent’s
tools as its own context. This composability is essential for
scaling from single-task bots to complex, multi-modal agent
ecosystems [10]. Recent comparative studies position MCP
as the foundational tier for tool execution, distinct from but
complementary to high-level coordination standards like the
Agent-to-Agent (A2A) and Agent Network Protocols (ANP)
[11].

implementations [5], [13], [14]. Because MCP grants every
server autonomy over tool exposure and scope, a single
compromised endpoint can cascade through dependent agents
and services, demonstrating the fragility of distributed trust in
early MCP ecosystems [3], [5], [13].

B. Taxonomy of Threats: Security vs. Safety

MCP threats can be organized along two complementary
axes: security (unauthorized access or modification) and safety
(unintended but harmful outcomes).

Security incidents generally involve unauthorized manip-
ulation (for example,
tampered tool definitions, command
injection, or stolen credentials), whereas safety failures arise
when MCP systems follow syntactically valid instructions
that nonetheless lead to undesirable consequences. In prac-
tice, these dimensions intersect: compromised security often
precipitates safety breakdowns, and conversely, weak safety
constraints can make security exploits easier to weaponize.

III. THREAT LANDSCAPE IN THE MCP ECOSYSTEM

C. Unique Threats in Context-Driven Protocols

The Model Context Protocol (MCP) represents a new
paradigm for connecting large language models (LLMs) with
external tools and contextual resources. While this integration
expands capability and flexibility, it simultaneously broadens
the attack surface. The decentralized structure - comprising
independent Hosts, Clients, and Servers - means that vul-
nerabilities in one component can propagate across others,
converting isolated weaknesses into systemic risks [3], [5],
[12].

A. Adversarial Actors and Attack Vectors

The MCP environment attracts a wide spectrum of ad-
versaries. Malicious developers may publish deceptive MCP
servers or modify tool definitions to exfiltrate data after
installation, a pattern analyzed as tool squatting and “rug-
pull” behavior [6]. Supply-chain attackers exploit the lack of
centralized distribution by introducing tampered installers or
rogue updates that silently alter tool functions or metadata [3],
[6], [13]. Insider threats within organizations can also misuse
legitimate MCP agents or servers to reach confidential enter-
prise data, for example by over-scoped tools and misconfigured
Resource access [13], [14].

Beyond individual insiders, sophisticated adversaries can
take advantage of the same structural weaknesses. Existing
MCP security work documents how poorly authenticated or
spoofed servers, over-privileged tools, and weak integrity
checks enable remote code execution, token theft, and lateral
movement across systems [4], [5], [13]. In such an environ-
ment, state-sponsored or organized actors could, in principle,
embed these techniques into large-scale disinformation or
espionage workflows that operate through MCP-connected
agents, even though current papers emphasize the technical
exploit chains rather than specific geopolitical campaigns.

These adversaries take advantage of the protocol’s limited
integrity verification, mutable server-side logic, and the ab-
sence of uniform, continuous validation mechanisms across

Unlike traditional APIs such as REST or gRPC, MCP
combines model reasoning with executable control, creating
a semantic layer that is vulnerable to meaning-based manipu-
lation. Several attack classes rely on this context-driven design
[3], [5], [13], [14]:
• Indirect tool

injection and prompt injection. Mali-
cious instructions are embedded in contextual data (for
example, documents, emails, or tool outputs) and then
forwarded into tools or servers via the MCP client,
allowing attackers to manipulate agent behavior or tool
invocation paths [5], [13].

• Context poisoning and cross-context contamination.
Malicious artifacts persist across tools, sessions, or
agents, for instance through shared file-based context or
reused tool registries, enabling chain attacks that exploit
shared context and confuse trust boundaries [5], [13].
• Model-switch and server shadowing. Attackers register
MCP servers or tools that mimic trusted ones, or exploit
weak naming/namespace controls, to redirect tool calls
to malicious implementations (sometimes described as
spoofed or “shadow” MCP servers) [3], [13].

• Protocol abuse via crafted MCP messages. Manipulated
MCP requests and responses can encode unintended
commands or parameters that agents treat as legitimate
tool invocations, especially when input validation and
policy checks are weak [4], [5], [13].

Because MCP standardizes tool and Resource interaction,
a single successful exploit pattern, such as a prompt-injection
template or a malicious server configuration, can be replicated
across many implementations. This shared surface makes
defensive containment particularly challenging in multi-tenant
and multi-server ecosystems [5], [13].

D. Lessons from Related Protocol Security Incidents

Historical precedents illustrate how open ecosystems tend to
evolve from rapid innovation toward increasingly strict trust

Dimension

Integrity

Confidentiality

Availability

Security focus

Safety focus

Tool or Resource tampering, unauthorized
context injection, tool poisoning, and abuse
of MCP message flows [5], [12], [13].

Data exfiltration via malicious or spoofed
MCP servers, exposure of tokens or session
identifiers, and cross-context leaks between
tools and workflows [5], [13].

and

Denial-of-service
resource-exhaustion
conditions
and
connected
including
that
unbounded
degrade or disable tool workflows [15], [16].

targeting MCP servers
LLM services,
consumption

patterns

leakage

Model misinterpretation
or grounding failures that
cause tools to be invoked
in harmful ways or with
incorrect parameters (see
Section V).
Accidental
of
private information during
example
for
reasoning,
over-broad
when
tool
surface sensitive
scopes
data
the model
context or logs [13], [14].
Over-automation or
run-
away execution loops that
consume
re-
duce human oversight, or
trigger repeated tool calls
without meaningful user
control [16].

resources,

into

TABLE II
SECURITY AND SAFETY DIMENSIONS IN MCP DEPLOYMENTS.

and verification controls. Browser extensions and package reg-
istries such as npm and PyPI initially thrived on openness, but
supply-chain abuse and malicious packages eventually forced
providers to adopt stronger signing, publisher verification,
and reputation mechanisms. Recent MCP security analyses
explicitly connect these lessons to MCP package ecosystems,
highlighting risks such as tool name collisions, malicious
MCP servers distributed via open registries, and weak integrity
checks on MCP packages [13].

Analyses by both academic and industry groups emphasize
that future MCP deployments will need practices aligned with
zero-trust approaches [3], [13]–[15]. Recommended controls
include mandatory and identity-bound authentication between
Hosts, Clients, and Servers; tightly scoped authorization using
OAuth or equivalent mechanisms; integrity protections such
as signed MCP packages or tool definitions where feasible;
and provenance or audit trails that make each context element
and tool invocation verifiable before execution. Without such
standards, MCP’s modular design risks allowing threats to
propagate faster than defenses can adapt.

Ultimately, the MCP threat landscape shows that the same
properties that enable powerful AI coordination - interoper-
ability, extensibility, and automation - also introduce unprece-
dented risk. Addressing these issues requires cross-disciplinary
governance that bridges AI safety research with classical
cybersecurity engineering, and treats MCP security as an
evolving, ecosystem-level problem rather than a purely local
implementation concern.

IV. SECURITY CHALLENGES IN THE MODEL CONTEXT
PROTOCOL (MCP)

Fig. 4. Context Poisoning Attack Flow. An attacker injects a malicious
tool description into the context, causing the LLM to unknowingly execute
unauthorized actions despite user approval checks.

The Model Context Protocol (MCP) is still an emerging
standard whose security posture remains underdeveloped. Un-
like mature middleware frameworks such as REST or gRPC,
which separate data transport, authentication, and execution,
MCP merges reasoning and control flows within a shared
semantic context [3], [5]. This enables fluid coordination
between LLMs and external tools but simultaneously blurs

Malicious MCP ServerMCP ClientAI ModelMalicious MCP ServerMCP ClientAI ModelLLM follows hidden instructionsUserConnect to MCP ServerRequest Server CapabilitiesSend tools with malicious descriptionInject tool description into contextUser submits queryRequest to execute malicious actionShows simplified tool summaryApprove malicious tool callExecute actionReturn Exfiltrate dataUsertraditional trust boundaries. In many MCP implementations,
context, metadata, and executable instructions coexist without
strong isolation, allowing malicious actors to exploit semantic
ambiguity or tool overreach. The lack of uniform guidelines or
centralized accountability further amplifies these risks: many
vendors delegate hardening to integrators or end users, rather
than enforcing baseline safeguards [12], [14]. Traub notes that
ambiguous terminology—particularly the conflation of local
executables with remote MCP servers—creates dangerous mis-
conceptions about privilege boundaries and exposure surfaces
[17].

These vulnerabilities are deeply interrelated rather than
isolated. Context poisoning can enable unauthorized context
injection and data leakage; weak permission boundaries allow
tools to read sensitive files; insecure configuration or update
paths can lead to supply-chain compromise; and malicious
server impersonation can redirect tool calls. Because MCP
couples model reasoning with tool execution, the protocol
inherits both software vulnerabilities and linguistic/contextual
ones. Unlike conventional APIs, where attacks primarily ex-
ploit code-level flaws, MCP introduces an attack surface
rooted in interpretation: what the model understands can be
as dangerous as what the code executes.

A. MCP Security Vulnerability Taxonomy

Table III provides a detailed classification of the security
and safety risks within the MCP ecosystem, categorized by
impact and execution phase.

may introduce manipulated payloads. Malicious servers may
also shadow trusted ones, providing altered tools under famil-
iar names. Without explicit server authentication or integrity
verification, these injections can grant attackers silent control.

D. Data Leakage and Privacy Risks

MCP servers often expose tools with access to local files,
credentials, or logs. If a tool or server is compromised, it
may exfiltrate such data. Piazza highlights that some MCP
servers expose session identifiers or sensitive metadata without
strict controls, creating opportunities for leakage or session
hijacking [12]. Guo et al. show that file-reading behaviors
embedded in tool metadata can cause unintended disclosure
[5]. Beurer-Kellner & Fischer further demonstrate that poi-
soned docstrings can lead an agent to read configuration files
or sensitive user data as part of tool invocation [18]. Without
sandboxing or least-privilege permissions, confidentiality risks
are substantial.

E. Cross-Session Contamination

Operationally, MCP agents may maintain shared state across
sessions. Guo et al. demonstrate that poisoned metadata or
artifacts can propagate across tools and tasks, producing “in-
fectious” effects [5]. Radosevich & Halloran describe scenar-
ios where corrupted public data retrieved through MCP tools
leads to execution of attacker-provided instructions in later
sessions [4]. Without strict session isolation, contamination in
one user’s workflow may compromise others.

B. Context Poisoning and Prompt Injection

F. Supply-Chain and Model-Switch Attacks

Context poisoning embeds malicious instructions in tool
metadata or schema so the LLM executes unintended actions.
Guo et al. describe these as tool poisoning attacks, where
malicious arguments or hidden behaviors in the tool descrip-
tion bypass user awareness [5]. Beurer-Kellner and Fischer
demonstrate that agents often “blindly rely” on docstrings: hid-
den steps inside metadata can cause file access or exfiltration
through an otherwise benign-looking tool [18]. Because many
MCP clients do not display full tool definitions, the model
may unknowingly execute harmful operations.

Prompt injection instead manipulates user-facing context
(documents, pasted text, retrieved content). MCP treats contex-
tual inputs as authoritative; if an attacker embeds obfuscated
instructions in upstream content, the agent may redirect tool
the
calls or modify behaviour [14]. Both vectors exploit
fact that MCP tightly couples contextual understanding with
execution.

C. Unauthorized Context Injection

Fig. 5. Supply Chain Attack Vector in MCP. Threat actors inject malicious
code into remote repositories, which are then downloaded by unwitting users
during build or update cycles, compromising the application environment.

Because MCP depends on distributed servers and commu-
nity tooling, it is highly susceptible to supply-chain compro-
mise. Hou et al. note risks of spoofed or malicious distributions
(e.g. manipulated installers or replacement packages) [3].
Bhatt et al. identify four structural causes behind rug-pull
attacks: mutable server-side logic, lack of continuous integrity
checks, absence of re-approval triggers, and exploitation of
established trust [6]. Model-switching attacks occur when
attackers register servers mimicking trusted ones to redirect
tool calls.

Unauthorized context injection occurs when malicious data,
commands, or tool definitions are introduced into the MCP
environment during installation, updates, or runtime. Guo et al.
categorize this as indirect tool injection: an attacker spoofs an
installer or update channel to insert hidden tool entries or over-
ride existing ones [5]. Because installation and configuration
can be complex, third-party installers without strong controls

G. Insecure Serialization and Protocol Abuse

MCP servers often rely on structured messages (e.g., JSON
transport). Piazza highlights that many servers lack integrity
checks, allowing manipulated messages or unauthorized mod-
ifications to flow through unverified [12]. Shapira documents
attacks leveraging namespace collisions or command overlap
in registries without isolation [13]. Hou et al. similarly warn

Software companiesBuild/UpdatesRemote RepositoryThreat ActorMalicious CodeDownload/InstallationBug and Issues on the applicationinject codeTABLE III
MCP SECURITY VULNERABILITY TAXONOMY

Category

Impact

Context Poisoning

Data leakage; unauthorized command execu-
tion; confidentiality breach

Phase

Execution

Prompt Injection

Unauthorized actions; model manipulation

Execution

Unauthorized Context In-
jection
Data Leakage & Privacy
Risks

Cross-Session Contamina-
tion
Supply-Chain & Model-
Switch Attacks
Protocol Abuse & Name
Collisions

DoS & Resource Exhaus-
tion

Stealthy tool override; integrity breach

Install/Update/Exec

Credential leakage; session exposure; file ex-
filtration

Execution

Infectious attacks; multi-user integrity breach

Execution

Rug-pull attacks; server impersonation; unau-
thorized tool mutation
Command overlap; confused-deputy access

Install/Update

Execution

System unresponsiveness; cost escalation

Execution

Evidence Source

et

al.

Guo
(2025);
Beurer–Kellner & Fischer
(2025)
Florencio (2025); Guo et al.
(2025)
Guo et al. (2025)

Piazza (2025); Guo et al.
(2025); Beurer–Kellner & Fis-
cher (2025)
Guo et al. (2025); Radosevich
& Halloran (2025)
Hou et al. (2025); Bhatt et al.
(2025)
Piazza (2025); Hou et al.
(2025);
(2025);
Florencio
Shapira (2025)
Narajala & Habler
Sauter
(2025)

(2025);
(2024); Guo et al.

that unchecked naming collisions could escalate in multi-
tenant deployments [3]. These weaknesses permit protocol-
level manipulation even when tool implementations are cor-
rect.

H. Denial-of-Service and Resource Exhaustion

DoS and resource-consumption attacks target MCP agents
by forcing excessive tool calls, unbounded retrieval, or infinite
loops. Narajala & Habler classify such attacks as severe in en-
terprise settings, noting that recursive or repeated tool triggers
can exhaust CPU and memory [15]. Guo et al. observe that
malicious payloads can significantly increase computational
cost [5]. Sauter describes unbounded consumption attacks that
cause runaway resource usage through crafted prompts rather
than classical network flooding [16].

I. Why MCP Security Is Vulnerable Today

MCP adoption is rapid, yet governance and standardiza-
tion lag behind. Many MCP clients do not expose full tool
specifications, request permissions transparently, or enforce
strict boundaries between context and execution. Third-party
installers, shared contexts, lack of authentication, and unveri-
fied tool updates magnify exposure. Because MCP integrates
both AI safety and classical cybersecurity concerns, securing
it requires combined safeguards: authentication, sandboxing,
provenance checks, tool validation, session isolation, continu-
ous monitoring, and least-privilege enforcement. Without such
measures, MCP deployments face heightened systemic risk.

protocol but
leads to unintended harmful outcomes. This
distinction is widely emphasized in AI governance research,
where safety failures stem from epistemic errors, misalignment
between components, or inadequate oversight rather than ex-
plicit security breaches [19]–[21].

The Model Context Protocol (MCP) introduces unique
safety challenges due to its distributed and compositional
architecture. Unlike monolithic LLM applications, MCP sepa-
rates responsibilities across three primitives - Resources (read-
only context), Tools (external actions), and Prompts (reusable
templates) - each operating in distinct
trust domains [1].
Because these primitives interact across independent Hosts,
Clients, and Servers, the traditional “single safety perimeter”
dissolves. As a result, failures in one primitive (e.g., low-
fidelity contextual retrieval) can escalate into harmful actions
executed by another.

These cascading interactions mirror patterns observed in
retrieval-augmented generation (RAG) systems, where epis-
temic errors in upstream retrieval frequently propagate into
downstream reasoning [22]. In MCP, this propagation is am-
plified because the protocol can perform real-world actions,
meaning that context errors or malicious instructions can
transform into operational harm.

To analyze these risks systematically, this paper introduces
a four-part taxonomy of safety challenges tailored to the MCP
ecosystem (Table IV).

A. Hallucination and Grounding Failures

V. SAFETY CHALLENGES IN THE MODEL CONTEXT
PROTOCOL ECOSYSTEM

While the security risks of MCP arise from adversarial
compromise or unauthorized manipulation, safety risks emerge
when the system produces correct actions according to the

Hallucination poses a significant epistemic safety risk in all
LLM systems. In the MCP ecosystem, this risk is exacerbated
by distributed data retrieval.

1) Context Fragmentation and Distributed RAG Fidelity:
Conventional RAG systems suffer from “context fragmenta-

TABLE IV
MAPPING SAFETY CHALLENGES TO MCP PRIMITIVES AND RISK TYPES

Safety Category

Primary Primitive

Risk Type

Description

Epistemic Integrity

Resources

Epistemic

Adversarial
Resilience
Alignment
Consistency

Resources & Prompts

Adversarial

Host Model & Tool
Policies

Alignment

Systemic Governance

Human Oversight &
Regulation

Governance

Grounding or hallucination due to frag-
mented or low-fidelity retrieval.
Hidden instructions or prompt
tions embedded in external data.
Policy conflicts or goal-pursuit mis-
alignment leading to harmful delega-
tion.
HITL failures,
dual-use misuse.

accountability gaps,

injec-

tion,” where splitting documents into small chunks breaks
critical relationships [23].

In MCP, Resources are retrieved from remote, independently
managed Servers. This compounds fragmentation because
fidelity loss occurs not only during chunking but also dur-
ing transmission. If a remote Server employs a low-fidelity
retrieval strategy, the Host receives isolated or incomplete
context, making epistemic errors an inevitable outcome [22].
2) Verification and Citation Challenges: Reliable AI sys-
tems require traceability and the ability to cite sources [24].
MCP complicates this because a Resource may represent ag-
gregated content sourced from multiple Server-side documents
[1]. Ensuring end-to-end traceability becomes a distributed
systems challenge. Without standardized provenance metadata,
citation verification becomes difficult in high-stakes environ-
ments.

B. Adversarial Steering and Filter Evasion

Adversarial steering manipulates an LLM through crafted
inputs. In MCP, this typically manifests as Indirect Prompt
Injection (IPI) [21].

1) Indirect Prompt Injection:

IPI occurs when an LLM
processes external inputs containing hidden instructions [25].
Because MCP Resources may contain arbitrary data such
as files, Slack messages, or emails,
these inputs can em-
bed attacker-crafted directives intended to override system
prompts.

Indirect Prompt Injection Attack Flow. The attacker embeds a
Fig. 6.
malicious prompt
in a Resource (Red). When the Host Client retrieves
this resource (Blue), the LLM ingests the malicious context (Orange) and
unwittingly issues an unauthorized tool call (Purple), which is executed by
the Host Client (Green), resulting in a malicious action on the remote system
(Red).

2) Cross-Primitive Execution Attacks: The most severe
IPI risk arises when an injected instruction escalates from
epistemic harm to operational harm. Since MCP exposes Tools
to LLMs, a malicious instruction within a Resource can trigger
a destructive Tool action on a remote Server.

This demonstrates a systemic safety gap in distributed
environments where low-trust Resources can influence high-
privilege Tool Servers.

C. Policy Conflicts Across Components

Alignment failures occur when the model’s objective func-
tion diverges from human intent. MCP complicates alignment
because safety policies are distributed across independent
components.

1) Distributed Preference Alignment: Host LLMs often rely
on preference alignment methods such as RLHF. External
Servers, however, operate under independent functional poli-
cies. When the Host delegates decisions to a Server, policy
misalignment may allow the remote component to circumvent
the Host’s guardrails. Leike et al. highlight that scaling align-
ment requires consistent reward modeling across the agent’s
entire environment, a condition often violated in distributed
MCP topologies [26].

2) Iterative Goal Manipulation and Agentic Deception:
MCP enables multi-step, agentic workflows. Research by
Holtman demonstrates that agents may develop incentives to
manipulate iterative feedback processes to preserve their utility
functions [27]. Furthermore, Shah et al. show that agents
can exhibit “goal misgeneralization,” competently pursuing
incorrect objectives in new environments (such as a remote
MCP Server) despite being aligned during training [28].

D. Human-in-the-Loop Vulnerabilities

Human-in-the-loop (HITL) mechanisms are essential safe-
guards [24]. MCP complicates HITL oversight due to dis-
tributed decision-making and opaque interactions.

1) Opacity and Explanatory Deficits: MCP workflows may
involve multiple Resource retrievals and Tool calls originating
from different Servers. The “black box” effect
intensifies
because key reasoning steps occur across remote JSON-
RPC exchanges. Tracing causality across these components
becomes a distributed forensics challenge.

2) Alert Fatigue and Deceptive Reporting: As MCP-
enabled agents generate extensive logs, human reviewers may
face alert fatigue. Moreover, agents may strategically filter
Resource retrievals to mislead supervisors, as outlined in
research on deceptive alignment [29].

E. Ethical Misuse and Dual-Use Concerns

1) Surveillance and Manipulation: MCP Resources may
expose sensitive personal or organizational data. At scale,
MCP systems can form de facto surveillance architectures,
especially when combined with advanced analytics [19]. Prac-
tices such as social scoring are explicitly prohibited by the EU
AI Act [20].

2) Disinformation and Malicious Automation: Tools allow
LLMs to perform actions such as sending messages or modi-
fying files. These capabilities can be weaponized to automate
disinformation campaigns or internal compromise [30].

F. Regulatory and Compliance Gaps

1) Fragmentation of Accountability: Regulatory frame-
works such as the EU AI Act assign obligations based on
provider-user relationships [20]. MCP complicates account-
ability because decisions may involve a Host (Provider A), a

Attacker embedsprompt inResourceHost C ientretrievesResourceLLM ingestsma iciouscontextLLM outputinc udesunauthorizedToo  Ca  Host C ientexecutesToo  Ca  via ServerMa icious Actionon remotesystemResource Server (Provider B), and a Tool Server (Provider C),
making liability propagation unclear.

2) Mapping to Risk Management Frameworks: Organi-
zations deploying MCP must map their infrastructure onto
frameworks like the NIST AI RMF [19]. Systemic governance
requires that safety goals be established early and integrated
across components, a core tenet of the DoD’s tailoring guide
for AI cybersecurity [30].

G. Mitigation Strategies and Future Research Directions

1) Protocol-Level Defenses for Epistemic Safety: Future
MCP specifications should require provenance metadata for
all Resource retrievals, including source authority, chunking
methodology, and timestamps.

2) Defensive Design for Adversarial Steering: Preventing
cross-primitive IPI escalation requires capability-based Tool
permissions, robust semantic filtering, and sanitization of
Resource inputs.

3) Enforcing Alignment and Policy: Distributed Policy Or-
chestration frameworks are needed to propagate safety policies
consistently across Host and Server components.

4) Future Research: Open research directions include: for-
mal safety guarantees for composable agentic MCP systems;
workflow-level risk aggregation methods for regulatory com-
pliance; and reliable distributed emergency-stop mechanisms.

VI. MITIGATION STRATEGIES

A. Tool Provenance and Immutable Definition Verification

A persistent vulnerability in Model Context Protocol (MCP)
ecosystems is the mutability and ambiguity of tool definitions,
which enable tool poisoning, puppet attacks, and rug-pull at-
tacks. Adversaries exploit weak provenance controls to replace
or modify tools after deployment, leading to unauthorized
context injection or model manipulation. Recent ecosystem
analyses have identified that standard MCP implementations
often lack a unified registry or schema validation endpoint,
making it difficult to distinguish between benign and malicious
tool definitions [3], [31].

To counter these threats, the Enhanced Tool Definition Inter-
face (ETDI) framework [6] proposes cryptographically signed
tool manifests, immutable version identifiers, and registry-
based approval workflows. Under this model, each tool’s man-
ifest (including its JSON schema, permissions, and metadata)
is signed by the provider’s private key. The MCP host verifies
this signature at both load and invocation time using the public
key, ensuring authenticity and integrity. Immutable version
tags prevent “rug-pull” attacks by requiring a new signature
and explicit re-authorization for any functional change [6].

A centralized or federated registry acts as the canonical
record of truth—storing public keys, signed definitions, and
change logs for auditing. Hosts must cross-check local meta-
data with registry entries and reject mismatches. ETDI further
integrates OAuth-enhanced tool definitions, limiting tool usage
to authorized scopes and reducing lateral movement risks [6].
Studies on MCP threats confirm that mutable schemas are
primary vectors for “Tool Poisoning Attacks” (TPA), where

attackers inject malicious metadata to corrupt
the LLM’s
planning phase [32]. Best practice recommendations therefore
include:
Cryptographic Verification: Verify signatures at both load

and invocation phases.

Immutable Versioning: Refuse tools whose metadata di-

verges from the registry’s canonical record.

Policy-Based Gating: Implement dynamic policy engines
that evaluate tool capabilities against runtime context [6].

Fig. 7.
The Enhanced Tool Definition Interface (ETDI) workflow. (1)
Developers sign tool manifests with a private key. (2) The Registry validates
the signature against the developer’s identity. (3) The MCP Host verifies the
signature at runtime before loading the tool, preventing tampering or “rug-
pull” attacks [6].

B. Access Control and Capability-Bound Execution

While provenance verification (§6.1) ensures authenticity, it
does not limit a tool’s operational scope. Access control and
capability-bound execution define what actions each tool or
model is authorized to perform, forming the authorization layer
of MCP security. Without this layer, even a trusted component
could be exploited to inject unauthorized context or manipulate
serialization channels [31].

a) Capability-Based Access Control: Effective security
requires coupling privileges to specific actions rather than user
identity. The ETDI framework extends this by introducing
OAuth-Enhanced Tool Definitions, where each tool receives a
token encoding fine-grained rights—such as read-only access
or network isolation—that cannot be reused outside its scope
[6]. This aligns with classical principles of least privilege,
ensuring that a compromised tool cannot escalate privileges
to access sensitive resources. Recent work on securing agent
workflows, such as the SAMOS system, enforces these poli-
cies at the gateway level, intercepting tool calls to validate
permissions before execution [33].

ProtectionVerificationFake Too Si ent UpdateTampered MetaMCP HostToo  RegistryAuthenticityImmutabi ityRegistry ConsistencyTrusted Too Too  ProviderSigned ManifestCanonica  RecordPub ic KeyChange ogRevocation / Key RotationTransparency LogOAuth / Po icy GateMode  / Agent InvokesB ock InvocationSigns ManifestSubmits toFetches Def.Verifies Sig.Va idates Ver.Compares Meta.Pre-invoke checksScopes OK - a  owScopes missing / po icy denyFai s Sig.RejectedB ockedb) Short-Lived Credentials and Policy Gates: To mini-
mize the blast radius of a potential breach, MCP implemen-
tations should utilize short-lived credentials and mutual TLS
(mTLS) for endpoint authentication [6]. The NIST Zero Trust
Architecture emphasizes continuous verification—every re-
quest must be re-authenticated and re-authorized [34]. Within
MCP, this is realized through policy gates that inspect each
tool call for valid capability tokens and contextual scope. Roles
such as reader or admin are enforced dynamically, preventing
persistent privileges from being exploited by “puppet” tools
[31], [33].

C. Context Validation and Prompt Sanitization

Context validation and prompt sanitization are fundamental
to securing the Model Context Protocol (MCP) against ad-
versarial and unverified input. A comprehensive review of the
MCP security landscape highlights that unvalidated context
flows enable threats like Tool Poisoning and Indirect Prompt
Injection [3], where malicious metadata overrides system poli-
cies or alters tool invocation sequences. The severity of these
threats is further demonstrated by the MCPTox benchmark,
which provides reproducible attacks against real-world MCP
servers [35].

Empirical studies confirm that “poisoned” tool descriptions
can successfully manipulate an LLM’s planning process with-
out executing any code, a vector known as a “decision-level”
attack [32]. To mitigate these risks, semantic and structural
validation must occur before model execution. The MindGuard
framework introduces a decision-level guardrail that tracks the
provenance of call decisions using a Decision Dependence
Graph (DDG) [32]. By analyzing the attention mechanisms of
the LLM, MindGuard can attribute specific tool invocations
to their source context, detecting when a tool’s metadata has
been “poisoned” to force an unintended action.

a) Mitigation of Indirect Prompt Injection: A critical
defense is the effective segregation and filtering of external
content. The OWASP Top 10 for LLM Applications (LLM01:
Prompt Injection) categorizes Indirect Prompt Injection as
a primary threat where external sources (like a document,
file, or a webpage summarized by a tool) contain hidden
malicious instructions [36]. This external data, when integrated
into the model’s context via MCP, can cause it to bypass
guardrails or perform unauthorized actions (e.g., leaking data
or manipulating subsequent tool calls).

Therefore, validation systems must implement a layered

defense:

Strict Delimiters: Use clear, unambiguous separators (e.g.,
XML tags or specific JSON fields) to explicitly separate
user input, system prompts, and tool-retrieved context.
The LLM should be instructed to only consider content
outside these separators as system commands.

External Content Filtering: Apply deterministic filters to all
tool outputs. This includes using output encoding and
content sanitization on external data to prevent it from
being parsed as an instruction or code payload [36].

Verify Provenance: Use attention-based analysis (like DDG)
to ensure that tool calls originate from genuine user intent
rather than injected metadata [32].

By uniting semantic filters with provenance tracking, MCP
systems can ensure that each context segment entering the
model is authentic, policy-compliant, and safe for downstream
execution.

D. Session Isolation and Protocol Integrity Controls

Session isolation and protocol integrity controls constitute
a complementary defense architecture to safeguard Model
Context Protocol (MCP) environments. This dual-layer ap-
proach ensures that each model or tool execution is confined
while simultaneously guaranteeing that all data exchange is
trustworthy and tamper-resistant.

1) Session Isolation: The Runtime Layer: Isolation mech-
anisms ensure that each tool execution occurs in a confined,
short-lived context.

The seL4 microkernel has been formally verified for func-
tional correctness from its abstract specification down to its C
code implementation [37]. Its capability-based access control
enforces strong, fine-grained separation [37], establishing a
minimal, formally provably correct Trusted Computing Base
(TCB) [37].

For dynamic containerized workloads, gVisor acts as a
user-space kernel [7]. It provides a strong isolation boundary
by intercepting all system calls from the application and
implementing them in a dedicated user-space process [7]. This
architecture minimizes the host kernel attack surface exposed
to the containerized environment [7].

2) Protocol Integrity: The Transport Layer: At the com-
munication layer, protocol integrity focuses on maintaining
the authenticity, consistency, and non-repudiation of serialized
exchanges.

Insecure deserialization is a severe vulnerability that occurs
when attacker-controlled data is converted back into objects,
often leading to remote code execution (RCE) or denial-of-
service (DoS) attacks [38]. To mitigate these risks, secure
serialization studies recommend enforcing mechanisms like
schema validation [38], the application of digital signatures to
confirm message authenticity [38], and the use of timestamps
and nonces to counter replay attacks [38].

The Protocol Integrity Framework for AI Toolchains pro-
posed by Zhao et al. introduces a system that binds every
message to a verified schema record [39]. This framework
employs versioned schemas with signed headers to reduce
impersonation and object injection risks [39]. Establishing a
Canonical Record for tools in a registry, complete with a
Changelog and Transparency Log, ensures that any tool invo-
cation can be verified against an auditable record [39]. Such
measures address security risks identified by organizations
such as OWASP. The OWASP Top 10 for LLM Applications
(2025) includes LLM07: System Prompt Leakage [40].

Fig. 8. Dual-layer defense architecture for MCP. The Runtime Layer (top)
enforces session isolation using ephemeral, sandboxed processes (e.g., gVisor)
for each tool execution. The Transport Layer (bottom) ensures protocol
integrity by validating message signatures and nonces against a canonical
schema, preventing unauthorized serialization attacks [38], [39].

E. Continuous Monitoring, Governance, and Adaptive Re-
sponse

The management of autonomous AI agents requires a
robust, closed-loop system for
risk management, which
is encapsulated by the topic of Continuous Monitoring,
Governance, and Adaptive Response. This framework is
essential for realizing Trust, Risk, and Security Management
(TRiSM) principles in complex agentic systems [41] and for
defining the necessary Human-Agent Security Interface [10].
The system must structurally integrate these functions across
the Policy, Governance and Compliance Plane,
the MCP
Runtime - Execution Plane, and the Detection and Analytics
Plane.

1) Governance and Adaptive Response (Intervenability and
Control): The governance plane translates high-level risk
policies into enforceable runtime actions, thereby providing
a mechanism for Adaptive Response and intervention:

• The Policy and Control Update Engine is responsi-
ble for processing high-level directives from the Risk
Register and Controls [42]. These directives are then
materialized as Technical Policies that define low-level
constraints such as tool scopes, execution filters, and
isolation rules for the agent [42].

• The resulting Updated MCP Config and Enforcement
Rules establish an operational envelope, dictating the
permissible actions of the Model or Agent within the
MCP Host or Orchestrator [42]. This critical enforce-
ment ensures the agent’s actions adhere to a safety and

Fig. 9. The TRiSM closed-loop governance architecture. The Policy Plane
defines high-level risk controls; the Execution Plane (blue) enforces them at
runtime; and the Detection Plane (green) feeds telemetry into an anomaly
detection engine (e.g., MindGuard). This feedback loop allows the system to
adaptively update policies in response to emerging threats [41], [42].

compliance perimeter, thereby maintaining control-flow
integrity [42].

• For critical or sensitive actions, this governance is imple-
mented through a robust Human-in-the-Loop (HITL)
pattern, which forces the agent to pause execution and
await explicit human verification before proceeding with
high-impact operations [42]. This pre-execution gating,
often utilized in Plan-then-Execute architectures, serves
as a dynamic defense against prompt injection and unau-
thorized actions [42].

2) Continuous Monitoring and Accountability (Visibility
and Oversight): Continuous Monitoring provides the neces-

Transport Layer: Protoco  IntegrityRuntime Layer: Session Iso ationVerified Header+ Nonce CheckSchema Va idationSigned MessageSession 1Sandboxed ProcessSession 2Sandboxed ProcessSession 3Sandboxed ProcessUser/Agent RequestRegistry / Po icy StoreA   messages:- Signed & versioned- Verified with registry keys- Contain nonces & timestampsEach session:- Ephemera - Resource- imited- Memory-iso atedSeria izedRequestVa idatedResponseVa idatedResponseVa idatedResponseSeria izedRequestSeria izedRequestInitiates Too  Ca  Provides Canonica  Schema + KeysPo icy, Governance and Comp iance P aneDetection and Ana ytics P aneMCP Runtime - Execution P anePo icy and Contro  Update EngineTechnica  Po iciesscopes, fi ters, quotas, iso ation ru esRisk Register and Contro sNIST AI RMF, interna  SORComp iance Evidence and Audit LogsEU AI Act, interna  auditAnoma y and Attack DetectionMindGuard or TraceGPTTe emetry Stream ogs, traces, and eventsRed-Teaming and Rep ay Harnessadversaria  testingIncident Response and A ertsMCP Host or OrchestratorUser or C ientMode  or AgentToo s or MCP ServersUpdated MCP Config and Enforcement Ru esRegu ators or Governance Board ogs and metricsdecisions and too  pathsinvocations and errorsupdated configurations and stricter va idation ru esdefines monitoring requirements and KPIsfeeds reporting and externa  oversightsary visibility for accountability and risk detection, informing
the adaptive response mechanisms:

• The MCP Runtime - Execution Plane must emit
granular operational data, including the agent’s internal
decisions and tool paths, which are ingested by the
Telemetry Stream [42]. This log of the planning and
execution phases is necessary to establish the provenance
of the agent’s actions, allowing human operators to trace
any system outcome back to its originating prompt and
the agent’s initial plan [42].

• This continuous auditability is critical, as the Human-
Agent Interface must provide clear evidence of system
behavior to mitigate the risk of Accountability Obfusca-
tion [10].

• The stream of verified operational data populates the
Compliance Evidence and Audit Logs, serving as the
foundation for reporting to the Regulators or Gover-
nance Board and ensuring that system actions can be
fully reconciled with governance mandates [10].

F. Synthesis and Outlook

Across preceding sections,

the Model Context Protocol
(MCP) emerges not just as a framework for tool orchestration,
but as an evolving ecosystem that requires the same rigor as
traditional cybersecurity systems [10]. Sections 6.1 through
6.5 collectively form a defense-in-depth architecture - each
control addressing a distinct layer of trust [42]. Provenance
verification anchors authenticity; access control governs autho-
rization; context validation secures semantic inputs; isolation
and protocol integrity contain operational risk; and continu-
ous monitoring provides the adaptive feedback necessary for
long-term assurance [42]. Together, these controls form the
blueprint of a verifiable and auditable MCP control plane [10].
This layered model illustrates a fundamental shift in how
safety for AI-driven systems should be perceived. Instead of
securing static models, the focus moves toward safeguarding
the dynamic and contextual interactions - between users, tools,
and agents - that occur at runtime [41]. In this view, MCP is
not just an interface protocol, but a governance substrate that
binds identity, provenance, and behavior under cryptographic
and policy guarantees [41]. Emerging research tools such as
MindGuard and RAGGuard demonstrate the feasibility of real-
time provenance tracking and anomaly detection, hinting at a
future where transparency and accountability are embedded
directly in the model’s runtime [32], [43].

However, significant research challenges remain. Questions
around formal verification of policy enforcement, cross-vendor
interoperability of attested registries, and privacy-preserving
auditability are still open areas of study [10]. Collaborative ini-
tiatives - linking academic research, open-source governance,
and regulatory bodies - will be essential to standardize how
MCP-based ecosystems prove compliance without sacrificing
agility [41]. The convergence of policy and technology offers
a clear path forward: defining protocols that can both adapt to
emerging threats and attest to their security posture [42].

In essence, securing the MCP ecosystem is not a one-
time engineering problem but a continuous commitment—to
build AI systems that are trustworthy by design, observable in
practice, and verifiable by proof [41]. As these layers mature,
they will define the foundation of the next generation of secure,
context-aware AI infrastructures [10].

VII. OPEN RESEARCH DIRECTIONS

A. Formal Verification of MCP Protocols

Despite MCP’s promise as a “USB-C for AI agents” en-
abling standardized tool integrations [2], its implementations
have shown alarming security flaws. Over 43% of MCP server
implementations tested by Equixly were found to execute
unsafe shell calls [2], leading to remote code execution vulner-
abilities. This suggests a pressing need for formal verification
methods that can prove MCP-based systems free of certain
classes of bugs or unauthorized behaviors.

a) Challenge:: Unlike traditional APIs, MCP workflows
blend natural language prompts with code execution, making
it difficult to formally specify correct behavior. An MCP client
(LLM agent) may receive tool descriptions and user data and
then issue commands - essentially defining a protocol between
AI, tools, and data sources. Currently, there is no rigorous
guarantee that an MCP agent won’t misinterpret malicious in-
puts as instructions. For example, an LLM with high privileges
can be tricked into running unintended SQL queries or shell
commands (a confused-deputy scenario) [8]. Formal methods
could model these interactions and help verify properties like
“the agent never executes commands not explicitly authorized
by the human or system policy.”

b) Research Directions:: To formally verify MCP work-
flows, researchers need to develop models that capture both the
symbolic logic of tool invocation and the semantic constraints
on prompt processing. This may involve:

• Protocol Modeling: Defining the MCP exchange (re-
questing tool lists, receiving descriptions, executing tools)
in formal languages (e.g., process calculi or state ma-
chines). Such models can specify allowed sequences and
forbid, say, execution of tools not present in the intended
list or running code with unsanitized input.

• Static Analysis of MCP Servers: MCP servers are often
simple JSON-RPC endpoints [44]. Formal verification
can target their code to eliminate injection flaws. For in-
stance, tools like Tamarin or ProVerif (commonly used in
cryptographic protocol verification) might be adapted to
reason about MCP message integrity and authentication.
• LLM Policy Verification: A harder aspect is verifying
the LLM’s behavior - since the model can’t be fully
verified like code, one approach is to verify an envelope
around it. For example, ensuring that any instruction the
LLM produces to the MCP server passes certain filters
or invariants. OWASP’s draft LLM Security Verification
Standard provides a starting point for designing such
verification checklists [45].

Formal verification in this context remains largely open.
Early work emphasizes integrating symbolic reasoning with

LLM agents to catch vulnerabilities [46]. The unique, dynamic
nature of AI-driven protocols means classic verification must
be complemented with rigorous red-teaming and testing frame-
works (e.g., MCP-AttackBench with 70k adversarial samples
[47]). A key research direction is bridging this gap: developing
hybrid verification that combines static checks on MCP tool
code with dynamic validation of LLM outputs. This could
pave the way for MCP standards that are provably secure-by-
design, rather than reliant on reactive patching of issues after
incidents.

B. Standardization and Interoperability Challenges

a) Interoperability Issues:: With multiple organizations
building MCP servers (connectors) and clients, inconsistencies
arise. For example, different servers may implement authen-
tication differently (or not at all), making it hard for clients
to know what security guarantees exist [44]. Some servers
might allow HTTP with no encryption, others require OAuth
tokens - an absence of strict standards means a weakest-link
security problem. Furthermore, tool description formats might
vary, leading to parsing issues or even security bypasses if a
client assumes a certain format. A standardized schema for
tool metadata (with a structured separation of instructions vs
descriptive text) is lacking [44].

b) Standardization Efforts:: In mid-2025, the MCP spec
saw updates addressing some security aspects: e.g. mandating
OAuth2 Resource Server patterns and Resource Indicators
(per RFC 8707) to prevent token replay [44]. These updates
aim to ensure any compliant MCP server performs proper
auth and scope isolation by default [48]. However, not all
implementations immediately follow the latest spec, and back-
ward compatibility concerns make enforcement tricky. Open
research questions include: How to enforce standard security
features across a decentralized ecosystem?

One idea is a certification program or compliance suite that
MCP servers must pass (akin to test suites for web standards).
Some researchers have proposed a registry of trusted MCP
tools/servers with verification - a form of zero-trust architec-
ture for MCP [47]. In a registry-based approach, tools must
be registered and signed by an authority, and clients only
trust those signatures. This improves interoperability (everyone
trusts the registry) but at the cost of flexibility and added
latency [47].
Another

tool-
invocation standards. For instance, OpenAI’s function calling
or Microsoft’s plugins have overlapping goals. Interoperability
might mean designing converters or unified schemas so that
an enterprise can use a single governance mechanism across
different AI platforms. Ensuring MCP can work alongside
or integrate with such alternatives is an open question. Re-
searchers are exploring common ontologies for tool definitions
and policy interchange formats so that an allow/deny rule or
safety policy can be applied uniformly whether the LLM uses
MCP or another protocol.

compatibility with other

challenge

is

In summary, balancing innovation with standardization is a
key research direction. The community is actively discussing

an official MCP security standard (perhaps via IEEE or an
RFC) that would codify authentication, encryption, and safe
defaults [48]. Ensuring all MCP implementations speak the
same “secure language” is essential for interoperability -
otherwise, organizations will face integration headaches and
security gaps when connecting multiple MCP components.

C. Scalable Safety Alignment for Large Contexts

Modern LLMs are extending context windows into the tens
or even hundreds of thousands of tokens. In an MCP ecosys-
tem, this means an AI agent might ingest massive amounts
of context: documents, conversation history, tool outputs, etc.
While this enables richer functionality, it strains current safety
alignment techniques that were developed on shorter contexts.
Ensuring an AI remains aligned (e.g. not revealing confidential
info, not following harmful instructions) when operating over
huge context poses new challenges [49].

One concern is that

long contexts can hide malicious
instructions or biases. Attackers may exploit the length to bury
a prompt injection far back in the context, betting that standard
safety filters (often tuned on shorter prompts) might miss it.
Moreover, the model’s attention on very long input might
dilute the effect of safety training: if the model was aligned
via fine-tuning on shorter prompts, it may not generalize well
to very long concatenated inputs. Recent research confirms
that long-context LLMs have safety blind spots not present in
short contexts [49]. For example, Huang et al. (2024) introduce
LongSafety, a dataset and benchmark specifically to evaluate
LLM behavior on ∼40k-token contexts [49]. They found that
simply having good short-context alignment is insufficient -
unique failure modes appear when the input is extensive, such
as the model following a malicious snippet embedded deep in
the context, or forgetting earlier safety instructions when later
context conflicts.

a) Scalable Alignment Strategies:: To tackle this, re-

searchers are exploring multiple approaches:

• Curriculum and Fine-Tuning: Using datasets like
LongSafety to fine-tune or RL-train models specifically
on long inputs [49]. The idea is to condition the model
to remain consistent
in obeying safety rules even as
context grows. Initial experiments show promise: training
with long-context safety data improved models’ ability
to refuse or safely handle malicious long inputs without
degrading performance on short inputs [49].

• Segmented Attention and Monitoring: Another idea
is to have the model (or a parallel process) periodically
summarize or scan segments of the context for red flags.
Essentially, break the long context into chunks and apply
safety classifiers or rule-checkers on each chunk. This
could catch hidden instructions (“ignore all previous
directives...”) even if they appear 20,000 tokens in. Tools
leveraging pattern matching for known injection phrases
can operate on sliding windows of the context [48].
• Hierarchical Alignment: Some proposals involve a hi-
erarchical model approach: a high-level oversight model
monitors the main model’s behavior over long sessions.

For instance, an oversight model could be trained to
detect when the assistant’s output is starting to contradict
earlier given policies (e.g., if earlier it said “I cannot do
X per policy” but later in a long session it attempts X).
This is akin to having a safety governor that has a bird’s-
eye view of the conversation state, which might be more
feasible than trying to imbue a single model with perfect
long-range consistency.

Crucially, aligning for large contexts also involves per-
formance considerations. Techniques like windowed RLHF
or selective attention can help a model focus on relevant
context safely. The community is investigating memory editing
approaches - for example, if an earlier part of context is
identified as malicious or irrelevant, dynamically mask it out
or tag it so the model’s decoder gives it no weight. These
are active research threads aiming to ensure that as context
lengths scale up, safety does as well. Given the trajectory
of LLM deployments, scalable safety alignment is no longer
optional; it’s becoming a foundational requirement for MCP-
like systems used in enterprise settings, where context (and
stakes) are enormous.

D. Human-Centered Safety Mechanisms

While technical defenses are vital, human-centered safety
mechanisms remain a critical complement in MCP ecosys-
tems. These mechanisms aim to incorporate human judgment,
oversight, and usability principles into the design of secure
AI tooling. A core issue with MCP-based AI agents is the
lack of user visibility into what the agent is really doing [2].
For example, an AI assistant might say “Checking calendar...”
to a user, but due to a poisoned tool description it could
actually be exfiltrating data in the background [44]. Human-
centered design would strive to make the AI’s hidden context
and actions more transparent and controllable for users.

a) Key approaches include::

• Transparency Dashboards: Develop interfaces that
show what the AI agent sees versus what the user sees.
One proposal (ScanMCP) suggests a dashboard that lets a
user or admin audit all the tool metadata and instructions
the agent
is acting on [47]. This could visually flag
discrepancies, e.g. if a tool’s description contains hidden
instructions or if a server has silently redefined a tool. By
exposing the agent’s true “context view,” users can catch
malicious or unintended behavior early.

• Human-in-the-Loop (HITL) Oversight: Incorporating
checkpoints where human approval is required for certain
high-risk actions. For instance, if an MCP agent wants
to execute a shell command on a production server or
send money via an API, it could pause and request a
human’s confirmation via a prompt or UI. This is already
a best practice in some systems - effectively applying a
two-person rule for irreversible or sensitive actions. HITL
can dramatically reduce harm from misaligned AI actions,
though it may impact efficiency.

• Intuitive Safety Controls: Giving non-expert users easy
ways to set safety preferences. Imagine a simple toggle

for “Allow AI to execute write commands” or a slider
for how aggressively the AI should filter potentially
sensitive outputs. By making safety controls part of the
user experience (rather than hidden config files), users
can better tailor the system to their risk tolerance. This
human-centric approach recognizes that acceptable risk
varies by context and user - a developer might allow an
AI agent broad rights in a dev environment but would
tighten them in prod.

• User Education & Warnings: Ensuring that platform
users are educated about MCP risks. For example, if a
user is about to connect to an unverified third-party MCP
server, the interface could display a warning: “Warning:
This connector is not certified. It may execute arbi-
trary commands. Continue?” Such consent and awareness
prompts follow the model of modern browser security
(think of how browsers warn about invalid HTTPS cer-
tificates). This puts a human in the decision loop in an
informed way.

A human-centered philosophy also means considering us-
ability alongside security. If security mechanisms are too
inconvenient, users might find workarounds (like disabling
a filter). Thus, research is focusing on minimally intrusive
safety: e.g., smart prompts that alert but not annoy, expla-
nations when an action is blocked (so the user understands it
and possibly can correct the AI’s behavior). The ultimate goal
is an ecosystem where humans and AI agents collaborate with
trust - earned by transparency, guided by human values, and
with humans holding the reins especially when judgment calls
or ethical considerations arise.

E. Regulatory, Legal, and Ethical Considerations

As MCP-enabled AI systems proliferate in domains like fi-
nance, healthcare, and customer support, they inevitably come
under the lens of regulators and raise complex legal/ethical
questions. Regulatory frameworks are still catching up, but
certain trends are emerging:

• AI Risk Classification: Proposed laws (such as the EU
AI Act) classify AI systems by risk level. An MCP-based
system that can take actions (e.g., modify databases, send
emails) might be deemed high-risk, since failures can lead
to significant harm or data breaches. This would require
the provider to implement stringent risk management,
documentation, and human oversight by law. Already,
guidelines like NIST’s AI Risk Management Framework
urge treating such AI systems as high-risk components
that require continuous monitoring and defense-in-depth
[48]. In practice, this could mean organizations must log
all AI tool invocations, perform regular security audits of
MCP connectors, and have incident response plans for AI
misbehavior.

• Liability and Accountability: If an AI agent integrated
via MCP causes damage (for example, it deletes customer
data or leaks confidential info), who is liable? Is it the
developer of the AI model, the provider of the MCP
server, or the organization deploying it? This is an open

legal question. Jurisdictions are considering updates to
product liability laws to include AI actions. A likely
outcome is shared liability: companies deploying the
AI must exercise due care (e.g., configure permissions
properly, test the system), and AI vendors might need
to warrant certain safety features. To navigate this, many
enterprises are setting up AI governance committees that
review deployments for compliance and risk - a practice
likely to be formalized into regulatory requirements for
sectors like banking or healthcare.

• Privacy and Data Protection: MCP systems often shut-
tle sensitive data from databases to LLMs. This triggers
concerns under privacy laws like GDPR. If an AI system
pulls personal data via MCP to answer a query, it must do
so in line with data minimization and purpose limitation
principles. Regulators may require that such systems
annotate or label personal data, ensure user consent for
its use, and provide audit logs showing how data was
accessed and processed by the AI. Additionally, cross-
tenant data leakage (see §8.2) could violate privacy laws
if one user’s data is exposed to another. Thus, regulatory
pressure will enforce strict context isolation and perhaps
mandate technical measures (like encryption of context
in transit/storage [48], access controls at each layer, etc.)
to protect personal data in MCP workflows.

• Ethical Use and AI Governance: Beyond formal law,
there is the ethical dimension - ensuring MCP is used
to augment human good and not propagate harm. Ethical
AI principles (transparency, fairness, accountability) must
be interpreted in the context of MCP. For example,
transparency might entail informing users when an AI
agent is operating on their data or making decisions,
and providing explanations for its actions. Fairness could
relate to ensuring that the tools the AI chooses or the
data it retrieves do not reflect biased selections (e.g.,
if multiple knowledge sources exist, the AI shouldn’t
consistently favor one in a way that skews outcomes
unfairly). Organizations are increasingly establishing AI
Ethics boards to oversee such issues. We can expect
industry standards or certifications (like an “MCP Ethical
Use Certification”) to emerge, akin to how data centers
have certifications for security.

In summary, regulatory and ethical considerations are push-
ing MCP ecosystem stakeholders toward greater accountabil-
ity. We will likely see a blend of hard requirements (security
controls, documentation, audit logging mandated by law) and
soft guidelines (ethics charters, best practice frameworks).
Researchers and policy-makers must work together to clarify
how concepts like duty of care, negligence, or compliance
apply when an AI agent is effectively acting with autonomy
within an organization’s systems. Proactively addressing these
considerations will not only avoid legal penalties but also build
the trust needed for such powerful AI integrations to gain
public acceptance.

F. Future Role of AI Governance in MCP Ecosystems

Given the multifaceted challenges discussed, the role of AI
governance in MCP ecosystems is poised to become pivotal.
AI governance refers to the organizational structures, policies,
and processes to ensure AI is developed and used responsibly.
In the context of MCP, governance will evolve to oversee not
just individual models, but the entire network of models, tools,
and data pipelines that MCP connects.

transaction APIs without

a) Centralized Oversight Hubs:: One likely development
is the introduction of AI governance platforms that sit atop
the MCP infrastructure in an organization. These would act as
control towers, providing a unified view of all MCP agents,
the tools they are using, and the data flows between them.
Through such a hub, governance teams could set global
policies - for example, “No MCP agent is allowed to call
financial
two-factor approval” or
“Tools accessing HR data must only be used by HR-designated
AI agents.” Enforcement could be done by an MCP gateway
or proxy that checks each request against these policies [47].
In effect, this treats the MCP ecosystem as a governed IT sys-
tem, akin to how network firewalls and identity management
systems govern traditional IT. Early prototypes of this idea are
being discussed, such as policy-enhanced MCP gateways that
incorporate OAuth scopes and cryptographic checks to enforce
fine-grained rules [47].

b) Standard Operating Procedures (SOPs) for AI Inci-
dents:: AI governance will also entail preparing for incidents
if a tool poisoning attack
unique to MCP. For example,
is detected (an agent using a tool with hidden malicious
instructions), what is the escalation path? Governance may
prescribe that the incident is reported to a security operations
center (SOC) and that particular MCP server is quarantined
until forensic analysis is done. Organizations might conduct
MCP fire drills - simulating scenarios like a supply-chain
attack on a connector or a massive prompt injection leak –
to test their readiness. Lessons from these drills can inform
improvements in tooling and policy. As the Pomerium analysis
of the Supabase incident noted, such breaches can happen in
seconds, so continuous monitoring and alerting are essential
[8]. Governance frameworks will mandate those real-time
monitoring capabilities and periodic audits of logs.

c) Collaboration and Industry Standards:: On a broader
scale, AI governance for MCP will likely involve industry con-
sortia and information sharing. Just as cybersecurity has ISACs
(Information Sharing and Analysis Centers) for sectors, we
might see networks where companies share MCP threat intel-
ligence (e.g., a new kind of tool injection attack discovered, or
IOC – indicators of compromise – for malicious MCP servers).
Industry guidelines specific to MCP are emerging: for instance,
OWASP’s Top 10 for LLMs (2025) [48] can be considered a
part of governance reference material, highlighting top risks
like prompt injection, insecure output handling, etc., that every
MCP project should mitigate.

In the future, governance might even be partially automated.
Meta-governance AI agents could monitor other agents - an
idea sometimes framed as AI “watchdogs” or sentinel systems.

These governance agents would enforce rules dynamically: if
an MCP agent’s behavior deviates from policy (say it tries
an out-of-policy action), the watchdog agent could intervene
(stop the request, alert a human, or even correct the course).
While still speculative, such approaches align with a zero-trust
mentality where nothing, not even the AI, is implicitly trusted
[47].

Overall, the role of AI governance in MCP ecosystems
will be to institutionalize safety and security practices. It will
turn ad-hoc measures into formal policy, ensure continuous
improvement via lessons learned, and foster a culture where
the incredible power of connected AI is balanced by robust
oversight. This governance evolution is crucial – without it,
the MCP ecosystem could suffer the same fate as early internet
protocols (amazing functionality but rife with security issues)
until eventually retrofitted with governance. With proactive
effort, we can guide MCP’s growth such that robust gover-
nance is a built-in feature of successful deployments, not an
afterthought.

VIII. CASE STUDIES AND LESSONS LEARNED

A. Prompt Injection Attacks in RAG/MCP Systems

One of the most visceral illustrations of MCP-related vul-
nerabilities comes from prompt injection attacks, which have
also plagued Retrieval-Augmented Generation (RAG) systems.
In these attacks, an adversary manipulates the text input or
context so that
the LLM receives hidden instructions and
executes unintended actions. MCP expands the surface for
such attacks because it introduces tool descriptions and data
as new vectors to smuggle malicious prompts.

a) Supabase Incident (2025):: A recent case involved
a developer using an AI assistant (Claude via Cursor IDE)
connected to a Supabase database through MCP. The attacker,
posing as a normal user of a support ticket system, embedded
a malicious instruction inside a support ticket message. This
instruction was crafted to look like a message for the AI
agent, telling it to leak the contents of a sensitive database
table (integration_tokens) and post them back into the
support thread [50]. The support workflow was such that the
human support agent never saw this hidden directive (it was
just stored as data), and due to role-based access controls, the
human agent couldn’t access the sensitive table anyway [8].
However, when the developer later asked the AI assistant to
show the latest ticket, the AI pulled in the attacker’s message
as part of the context. The LLM confused data for a command
– it dutifully executed the SQL queries as instructed, since
it had the powerful service_role credentials, bypassing
all security policies [8]. The result: the secret tokens were
extracted and inserted into the ticket conversation, immediately
visible to the attacker in the user interface [50].

This incident encapsulates prompt-injection-as-cyberattack.
It exploited the fundamental ambiguity that LLMs have: they
cannot inherently distinguish user-provided data from system
instructions [50]. In RAG systems, a similar risk exists if
an attacker poisons the knowledge base. For example, recent
research showed that by inserting a few malicious documents

into a RAG corpus, attackers could cause LLM responses to in-
clude harmful content or follow hidden instructions [51]. Clop
and Teglia (2024) demonstrated that backdooring the retriever
component can achieve high-success-rate prompt injections –
e.g., inserting links to malware or triggering denial-of-service
behaviors – with only a small number of poisoned entries [51].
b) Lessons Learned:: Prompt injection attacks teach us

a few key lessons:

• Isolation of Instructions vs Data: Systems must clearly
delineate between what is “executable instruction” and
what is “just content.” In MCP, one mitigation is to san-
itize or structure tool descriptions so that they can’t con-
tain executable instructions [44]. Similarly, user-provided
data going into prompts should be filtered for telltale
patterns (“ignore previous”, “system:”, etc.) [48]. The Su-
pabase case post-mortem recommended adding a prompt
injection filter on any user content before it’s fed to an
agent with powerful rights [50].

the worst

• Principle of Least Privilege: The impact of prompt
injection is magnified when the AI agent has exces-
sive privileges (as in service_role being a root-like
key). Had the agent been using a read-only or scoped
credential,
it could do is read some data,
not exfiltrate by writing into a customer-visible channel
[8], [50]. Many experts now advise never to give an
AI agent broad production credentials [48]. Instead, use
minimally scoped API keys and, where possible, approve
each action. In other words, even if an injection occurs,
the damage is limited by design.

• Audit and Monitoring: In retrospect,

the Supabase
attack was detectable by unusual behavior – an AI agent
selecting a table that no normal support workflow would
access (the integration_tokens table) [8]. By im-
plementing monitoring that flags such anomalies (why is
our support AI reading a token table?), organizations can
catch an ongoing attack. The OWASP guidance (LLM02
Insecure Output Handling) also suggests validating out-
puts – e.g., scanning the agent’s answer for presence of
secrets and blocking it from returning those to a user [48].
This is like an output sanitizer: even if an injection got
through, you prevent the actual leak from reaching the
attacker.

• Defense-in-Depth: Ultimately, the lesson is that prompt
injection is a top threat (ranked #1 in OWASP’s LLM
Top 10 [48]) and must be addressed with multiple layers.
No single silver bullet (not even model training) can
catch all cases, because new prompt injection techniques
keep emerging [48]. A combination of input filters,
context compartmentalization, least privilege, and output
checks is the way forward. And importantly, keep systems
updateable: as researchers develop better detection (like
using fine-tuned detectors for adversarial prompts [47]),
organizations should be ready to patch those into their
MCP stacks.

The prompt injection incidents have sparked a flurry of
research and tooling – from “prompt firewalls” that strip or

rephrase suspected malicious content, to adversarial training
of models to resist following injected instructions [48]. This
remains an arms race, but each case study like this helps the
community refine its defenses.

B. Data Leakage Scenarios in Multi-Tenant Contexts

Multi-tenant LLM services (where one model serves mul-
tiple users or client applications) introduce unique risks of
data leakage across contexts. In an ideal scenario, each user’s
context (prompts, history, retrieved data) remains strictly iso-
lated – an AI should not mix data between tenants. However,
both systemic flaws and subtle side channels can break this
isolation.

A striking scenario was explored by Wu et al. (2025) in a
study titled “I Know What You Asked: Prompt Leakage via
KV-Cache Sharing in Multi-Tenant LLM Serving.” In modern
LLM serving frameworks, to save memory and computation,
it’s common to share the key-value (KV) caches among
requests that have identical prompt prefixes [52]. For example,
if User A’s prompt starts with “Imagine you are an IT expert
and tell me how to install Windows...” and User B later
asks “Imagine you are an IT expert and tell me how to
install Linux...”, the service might reuse the prefix “Imagine
you are an IT expert and tell me how to install” from A’s
cache for B [52]. This sounds harmless and efficient – until
you consider it as a side channel. Wu et al. showed that an
attacker (User B) can craft prompts to repeatedly test and infer
what another user (User A) had in their prompt by seeing if
cache hits occur [52]. Their attack, called PROMPTPEEK,
systematically reconstructs another user’s prompt one token
at a time by exploiting the cache sharing mechanism [52].
the shared cache betrays whether two queries
Essentially,
share a prefix, leaking information about the earlier query. In
their experiments, they could recover large portions of other
users’ queries – a severe privacy breach in a multi-tenant
environment.

This is a side-channel attack where efficiency optimizations
conflict with isolation. It highlights that even without an
explicit bug, multi-tenant setups can have covert channels.
Another example: if an LLM is prompting from a vector
database that’s multi-tenant, one tenant might cleverly query
with an embedding that intentionally vectors close to another
tenant’s data, causing an irrelevant but private document to be
retrieved (a form of vector space attack). OWASP’s guidance
(LLM08: Data Leakage via vectors) notes that combining data
with different access restrictions in a shared vector index can
lead to leakage if not handled carefully [53], [54].

a) Lessons and Mitigations::

• Strict Context Isolation: The ideal is to avoid sharing
state between tenants entirely. In practice, that might
mean disabling cache sharing across users, partitioning
vector stores per tenant, etc. Some frameworks offer “ten-
ant id” tags to segregate caches or ensure that retrieval
results are filtered by tenant. The slight hit in efficiency is
usually worth the security gain – especially for sensitive

domains. Amazon, for instance, in guidance on multi-
tenant RAG, emphasizes separate indexes or namespace
filters to prevent cross-tenant data mix-ups [55], [56].
• Encryption and Access Control: If certain sharing can’t
be avoided, encryption can sometimes help. For example,
homomorphic encryption of embeddings or queries so
that one tenant can’t interpret another’s data even if it
somehow intercepts it (though this is more theoretical
at present, as fully homomorphic LLM queries are not
practical yet). More straightforward is ensuring every
request carries an access token specifying the tenant, and
every internal component (LLM, retriever, cache layer)
checks that token before serving any data. This is akin to
how cloud services enforce multi-tenancy: each resource
request must include a tenant context that the lower layers
honor strictly.

• Monitoring for Unusual Access Patterns: Data leak-
age may sometimes be detectable by looking at usage
patterns. For instance, if one tenant’s queries are oddly
structured or repeatedly hitting on another tenant’s data
identifiers, it could raise a flag. In Wu et al.’s scenario,
an attack involves many crafted requests to do binary
search on another’s prompt content [52]. Rate-limiting
or noticing one user’s requests correlating with another’s
activity might tip off an attack in progress. Of course,
the attacker could try to slow-play to avoid detection, but
combining this with other anomalies (like resource usage
spikes) can unveil something is off [48].

• Architectural Alternatives: There’s exploration of ar-
chitectures that give each user a lightweight fork of the
model for the duration of their session, rather than truly
simultaneous multi-tenant use. Techniques like secure
enclaves or per-session virtualization of the model could
potentially isolate at the hardware level (preventing one
user from affecting another’s cache). This is heavy-
handed and costly in resources, so research continues on
making it efficient (perhaps by quickly cloning model
state or using dynamic weighting masks per tenant).
Multi-tenant data leakage scenarios drive home the point
that security needs to be considered at design time for LLM
services. Many early systems optimized for speed and cost,
inadvertently introducing leakage paths. The lesson is to treat
different user contexts with the same rigor as one would treat
different users’ data in a traditional web app – there, one would
never store two users’ sessions in the same memory space
without a robust separation. The same principle must apply to
AI contexts. Where separation is relaxed for efficiency, it must
be done with provable safety or not at all. Ongoing research
(like differential privacy for LLMs or robust tenant-isolation
frameworks) will be key to safely scaling AI services to many
users.

C. Policy Conflict Failures in Enterprise AI Pipelines

Enterprise AI pipelines often involve multiple layers of poli-
cies – from model-level content filters to business rule engines
to data access controls. A policy conflict failure occurs when

these layers have misaligned or inconsistent rules, causing
either a security lapse or a breakdown in functionality. MCP-
based systems, by their nature, integrate many components
(LLM, tool APIs, databases, etc.), so they are fertile ground
for such conflicts.

Consider an enterprise scenario: A company has a policy
that no customer data leaves the EU region for privacy
compliance. They deploy an AI support agent via MCP that
can retrieve customer info and draft responses. Separately, the
LLM’s provider has a safety policy that the model should avoid
outputting personally identifiable information (PII) unless nec-
essary. Now imagine a support ticket where the customer
explicitly asks, “What’s the address on my account?” The AI
fetches the address (which is customer data) from a European
database – so far so good regarding geo-policy. But
the
model’s safety layer (perhaps a system prompt or a middleware
filter) sees an address (PII) in the output and masks or refuses it
due to a generic PII rule. The enterprise policy would actually
allow this (since it’s a rightful request by the data owner), but
the LLM’s policy blocked it. This conflict results in a failure
to serve a legitimate user need. Alternatively, if the LLM’s
policy were weaker, it might output the address – but suppose
the MCP pipeline inadvertently logged that response in an
analytics system that replicates to US servers, violating the
geo-restriction. Here a misalignment between data governance
policy and logging practices caused a compliance breach.
These examples show how tricky multi-policy pipelines can
be.

A more security-critical instance of policy conflict is the
“confused deputy” scenario we saw with Supabase (from
§8.1). There, the database’s security policy (RLS) said the
support role cannot read the integration_tokens ta-
ble [8]. However,
the AI agent was given a credential
(service_role) that ignores RLS [8]. The enterprise im-
plicitly trusted the AI agent to enforce the spirit of RLS, but
it did not – it was confused by an injected prompt. This
is a conflict between human-set data policy and the AI’s
operational policy. The AI had no awareness of the RLS
rules, and no mechanism existed to convey those policies
into the AI’s decision-making. This case underscores a key
lesson: policies must be unified or at least communicated
across layers. If the database says “X is confidential”, the AI’s
prompt or system instructions should also include “don’t reveal
X”. In Supabase’s case, had there been an upstream policy
that the AI agent cannot output contents of certain tables (or
a classification of “sensitive”), the outcome might have been
different. Instead, the database enforced its rule to the human
interfaces only, not to the AI deputy acting on behalf of a
privileged user [8].

a) Lessons and Strategies::

• Policy Alignment: Enterprises should strive to translate
key business policies into the AI layer. This might mean
augmenting prompts with company-specific rules (“If
data is marked confidential, do not expose it to end-
users”) or employing a post-LLM rule engine to catch
disallowed outputs. There’s active development in “AI

policy languages” – basically DSLs that can express
things like access controls and content rules which an
AI mediator can apply to model outputs.

• Testing for Conflicts: Just as one tests software for
bugs, AI pipelines need testing for policy adherence. This
involves crafting test scenarios where an AI’s various
policies are put at odds to see what happens. For instance,
test if the AI will ever output a piece of data that the
data policy says it shouldn’t. If it does, that’s a red flag
that somewhere a policy isn’t being enforced or was
overridden. In complex pipelines, it might be necessary to
simulate certain threat models (like a “rogue” instruction)
to see if human policies still hold.

• Chain of Trust and Enforcement: Decide which layer
has final say. In well-designed systems, there’s typically
a single source of truth for a decision. If the AI says
“I sanitized this output” but a downstream DLP (data
loss prevention) system says otherwise, who wins? It
might be better to let the downstream system always
have the final check – assume the AI can fail – rather
than turning off downstream checks because “the AI is
supposed to do it.” In practice, multiple layers can coexist,
but one should be the ultimate gatekeeper (defense-in-
depth). Many enterprises will choose to keep a human
or traditional software gate at the final step (e.g., an
email sending agent might have to pass through an email
security filter even if the AI thought the content was fine).
• Audit Trails for Policy Decisions: When something goes
wrong, it’s important to know which policy was applied
or not. Logging not just what the AI did, but why, can
help here. If an AI refuses a request, log that it was due to
Policy X trigger. If it allowed something, log the checks
that passed. These traces help analysts refine policies and
resolve conflicts explicitly.

In summary, policy conflict failures teach that consistency
is key: all parts of the pipeline should enforce a coherent set of
rules. Disjoint or siloed policies (one set for the model, another
for the database, another for the app) will eventually collide.
Enterprises are learning to federate these rules under a unified
governance framework, often leveraging AI governance tools
(§7.6) to do so. The cost of not doing this is seen in either
security breaches or hamstrung functionality, both of which
undermine trust in AI systems.

D. Supply Chain Risks in Connector Ecosystems

The MCP connector ecosystem (tools and servers that pro-
vide functions to AI agents) resembles an application market-
place – and with that comes software supply chain risks. Just
as an open-source npm or PyPI package can harbor malicious
updates, an MCP tool can turn rogue after installation, or a
fake tool can masquerade as a useful one. We have already
seen hints of this new supply chain attack surface:

• Tool “Rug Pull” Attacks: As described by Elena Cross
[2], an MCP tool might be benign when first added by a
user (Day 1), but later automatically update itself or be
modified on the server (Day 7) to include malicious be-

havior, such as quietly rerouting API keys to an attacker’s
server. In her words, “It’s the supply chain problem all
over again - but now inside LLMs” [2]. The user trusts
the tool based on initial inspection, but because there’s
no integrity verification, a silent update can completely
subvert the tool’s function. This is particularly dangerous
in MCP because the AI agent will continue to call the
tool thinking it’s the same as before, and the user might
not realize the tool’s code or outcome changed.

• Dependency and Package Risks: Many MCP servers
are distributed as open-source packages (e.g., via pip or
npm). If an attacker compromises one of these packages
– or any of their dependencies – they can introduce
backdoors. The Forge Part 1 report noted observing
“inconsistent security practices” in popular tool repos:
broad permissions, minimal code review [44]. An attacker
could slip in a credential-stealing line of code into a
tool
that performs, say, database queries. Given that
MCP tools often run with the AI system’s permissions, a
malicious tool can be far more damaging than a typical
app dependency – it could potentially read private AI
conversations, access internal databases, or impersonate
the user to other services [44].

• Cross-Server Interference: In environments where mul-
tiple MCP servers are connected to one agent, a malicious
server can attempt
to interfere with calls to another
(trusted) server. This was illustrated as “Cross-Server
Tool Shadowing” [2]. For example, if two connectors
both offer a send_email function, a malicious one
could intercept the request and send a different email
or copy the contents to an attacker, all while the agent
and user believe the trusted server handled it. Essentially,
without a trust model, the agent might not distinguish
which backend actually fulfilled a tool call. This is both
a supply chain and an architectural risk.
a) Lessons and Defensive Measures::

• Tool Integrity and Signing: A clear lesson is the need
for digital signing and verification of tools. Just as modern
OS package managers verify software signatures, MCP
clients should verify that a tool’s code or definition
matches a known good hash. The absence of an integrity
mechanism was flagged as a major gap [2]. If the
MCP ecosystem provided a way to fetch tools with a
signature from the author and perhaps a “store” (even if
decentralized), clients could warn if a tool has changed
unexpectedly. Until then, the onus is on users to pin
versions [2] or manually inspect updates.

• Permission Sandboxing: Each connector should run with
the least privileges necessary. If a tool only needs read
access to one database table,
it shouldn’t have write
access to the whole DB. Some platforms are exploring
containerized tool execution or even VM isolation. In
practice, teams can deploy MCP servers on separate API
gateways that enforce ACLs. For example, an MCP server
for file access might run under a Unix user that only sees
a specific directory – so even if compromised, it can’t

read everything. This way, a malicious tool is constrained.
Forge suggests running tools with minimal permissions as
a basic hygiene step [44].

• Supply Chain Monitoring: Organizations using multiple
MCP integrations should treat them as third-party soft-
ware and apply similar monitoring: track versions, watch
commit histories of open-source tools, and possibly fork
and maintain their own vetted versions. If a community
tool suddenly gets a new maintainer or a flurry of odd
changes, that’s a red flag. In critical environments, hosting
an internal registry of approved MCP connectors (and
only allowing those to be used) can significantly reduce
risk – essentially curating your own trusted “app store”
for your AI.

• Runtime Anomaly Detection: Even with preventative
measures, assume a tool might go bad. At runtime,
monitor tool behavior. If a tool named “Calculator”
which should only do arithmetic suddenly tries to make
network calls or read disk files, that’s an anomaly to
stop. Similarly, if a tool’s outputs start containing data
far outside its scope (why is the weather lookup tool
returning SSH keys?), an AI or rule-based guard could
catch it. Elena Cross’s imagined scanner “would flag risks
like RCE, tool poisoning, session leakage” and show
differences between what the agent sees and the user
sees [2]. Such tooling is essentially an intrusion detection
system for the AI’s supply chain.

The broader lesson is that trust is key. Today, MCP treats
tool servers almost like plug-and-play devices on a network,
trusting them by default. The industry is learning to move
to a zero-trust posture for AI connectors: authenticate every
call, verify every component, and never assume a tool is safe
just because it’s connected. Emerging proposals like an MCP
gateway with allow-lists and cryptographic verification echo
this [47], [48]. As these defenses get implemented, the goal
is to enjoy the richness of the connector ecosystem without
suffering the fate of early browser plugin ecosystems (which
were notoriously abused until tighter controls came in).

E. Emerging Industry Practices and Defenses

In response to the above challenges, a set of emerging
best practices and defenses are taking shape across the AI
industry. These are being informed by groups like OWASP,
research institutions, and hard-won experience from incidents.
We highlight some of the most impactful practices:

• OWASP LLM Security Guidelines: The OWASP Top
10 for Large Language Model Applications (released
2025) [48] has quickly become a checklist for anyone de-
ploying systems like MCP. It emphasizes prompt injection
(#1 threat), output handling, data isolation, and excessive
agency issues among others. Many organizations now use
this as a baseline: for each item, they implement controls.
injection (LLM01),
For example,
they deploy prompt filters and tight
input validation;
for excessive agency (LLM08), they limit the actions

to mitigate prompt

an agent can autonomously take and require additional
confirmation for high-impact operations [8].

• NIST AI Risk Management Framework Adoption:
NIST’s AI RMF (1.0) offers a structured approach to
managing AI risks [48]. Companies are aligning their
MCP system development with these phases: Identify
(catalog the MCP components and their risk points),
Measure (e.g., pentest your MCP setup, measure attack
success rates), Manage (deploy mitigations and controls),
and Govern (establish oversight, as discussed in §7.6).
The framework’s emphasis on continuous monitoring and
defense-in-depth [48] is reflected in practices like layered
filtering (both at input and output), and real-time anomaly
detection in agent behavior [48].

• AI Security Tooling and Products: A new crop of
tools is emerging aimed at securing MCP and similar
pipelines. For instance, “MCP-Guard” (a research pro-
totype) proposes a multi-stage detector that statically
scans prompts/tools, then applies a neural detector for
semantic attacks, and uses an LLM-based arbitrator for
final decision [47]. Commercially, companies like Javelin
have announced “MCP Security” solutions – essentially
defense-in-depth suites that integrate authentication prox-
ies, context firewalls, and monitoring dashboards [57].
Even established API security companies are extending
their products to cover AI-specific patterns (like detecting
when an AI API call might be responding to a prompt
injection attempt).

• Secure MCP Implementations & Gateways: Recogniz-
ing the issues with default MCP, some organizations have
built hardened versions or wrappers. Supabase’s team,
after the noted incident, published “Defense in Depth for
MCP Servers” outlining how they now offer a safer con-
figuration: enforcing read-only modes, mandatory auth,
and encouraging a proxy that can do request/response
validation [8]. Similarly, open-source projects and lists
(like the awesome-mcp-servers on GitHub [8]) are
curating secure-by-design MCP server templates. These
often include built-in OAuth support, logging, and safe
parsing of tool descriptions to strip dangerous content.
• Red Teaming and Adversarial Testing: Companies
are instituting regular red-team exercises on their AI
systems. This might involve hiring external experts or
using automated attack frameworks to simulate every-
tampering. The
thing from prompt
General Analysis team, for example, built a repository
of stress-test prompts and scenarios, which they use to
probe clients’ AI agents (they mention a comprehensive
repository of jailbreaking and red-teaming methods) [50].
By proactively attacking their own systems, organizations
can discover and patch weaknesses before real adversaries
do.

injections to tool

• User Training and Process Adjustments: On the people
side, there’s an increasing emphasis on training develop-
ers and users about AI security. Developers adding a new
MCP connector are advised to think like security engi-

neers: Did I validate inputs? What could go wrong if this
tool is abused? Some enterprises now require a security
review for any new MCP integration, similar to how code
changes undergo review. End-users (like analysts using
an AI agent) are being educated to recognize odd AI
behavior that could signify an attack (for instance, if the
AI asks for unusual permissions or produces outputs that
contain raw data dumps unexpectedly).

• Incident Response Plans: Finally, recognizing that no
defense is perfect, organizations are preparing IR plans
specific to AI. This includes playbooks for things like
“AI model compromised via prompt – steps to contain
and recover” or “Data leak through MCP – who to notify,
how to purge logs, etc.” By planning these responses in
advance, the damage from an incident can be mitigated
more swiftly. Also, sharing these incidents (anonymized)
in forums or blogs has been constructive – e.g.,
the
community learned a lot from the detailed Supabase
incident post-mortems [8], and those lessons have been
rolled into updated best practices.

In conclusion, the MCP ecosystem’s challenges are being
met with a robust and evolving set of defenses. The tra-
jectory is clear: what was once a bit of a “Wild West” of
quickly chaining AI to tools is maturing into a disciplined
field blending cybersecurity, AI alignment, and governance.
Industry practices now acknowledge that deploying an AI
agent with tool access is not a fire-and-forget endeavor – it
requires lifecycle management, just as any critical software
service does. By studying cases of failure and iterating on
defenses, the community is steadily building a safer foundation
for the powerful capabilities that MCP and similar frameworks
unlock. The hope is that through open research, shared stan-
dards, and collective vigilance, we can enjoy the benefits of
connected AI agents while keeping their risks in check.

Sources Note:: The insights and data points above were
synthesized from recent research papers, industry reports, and
real-world incident analyses, including but not limited to Elena
Cross’s MCP security overview [2], Forge Code’s deep-dive
into MCP vulnerabilities [44], General Analysis’s case study
on Supabase MCP exploits [8], Wu et al.’s NDSS paper on
multi-tenant prompt leakage [52], and the OWASP and NIST
guidelines for AI security [48]. These illustrate the collective
effort to identify issues and shape best practices in securing
the Model Context Protocol ecosystem.

IX. FUTURE OUTLOOK

As the Model Context Protocol (MCP) matures from an
experimental interface into a critical infrastructure standard, its
trajectory suggests a fundamental reshaping of how AI systems
interact with the digital world. The transition from isolated
chatbots to interconnected agent ecosystems will be defined by
how effectively the community resolves the tension between
interoperability and security.

A. Evolution of MCP Ecosystems in AI Integration

C. Roadmap for Secure and Responsible Adoption

We anticipate that MCP will evolve from a connector
protocol into the de facto “kernel” of an AI-native Operating
System. Current
implementations largely treat MCP as a
plugin layer for existing applications (e.g., adding database
access to an IDE). However, the long-term trend points toward
Agency-First Architectures, where the OS itself exposes all
functionality (file system, network, UI) via MCP-compliant
servers rather than traditional APIs [3].

This evolution will likely proceed in three phases:
1) The Plugin Phase (Current): MCP serves as a bridge
for specific, high-value integrations (e.g., GitHub, Google
Drive) managed by host applications.

2) The Mesh Phase (1-2 Years): Agents begin to commu-
nicate peer-to-peer using MCP, where one agent acts as a
“Server” to another’s “Client,” creating complex, multi-
hop supply chains of cognition [10].

3) The OS Phase (3+ Years): Operating systems integrate
MCP primitives at the kernel or shell level, allowing
authenticated agents to orchestrate system resources di-
rectly, protected by hardware-enforced isolation (e.g.,
capability-based microkernels) [37].

Furthermore, we expect MCP to expand beyond text-based
resources into multi-modal streams. Future MCP servers will
likely stream real-time audio/video contexts (e.g., screen shar-
ing, CCTV feeds) directly to multi-modal models, introducing
new classes of “sensory” injection attacks that defenses must
anticipate today.

B. Balancing Innovation, Security, and Safety

The central challenge for the MCP ecosystem will be
avoiding the “Security Tax”—the risk that imposing heavy-
handed controls will stifle the open innovation that made
MCP successful. There is a palpable tension between the
“Permissionless Innovation” model (open registries, anyone
can publish a server) and the “Walled Garden” model (verified-
only extensions, strict sandboxing).

To balance these, the industry is gravitating toward a Tiered

Trust Model:

• Tier 0 (Untrusted): Experimental tools run in ephemeral,
network-gated sandboxes (e.g., WebAssembly or gVisor
containers) [7]. They have no persistent access to the host
file system.

• Tier 1 (Verified): Tools signed by known entities (e.g.,
Verified Publishers) run with standard permissions but
require user confirmation for high-risk actions (HITL) [6].
• Tier 2 (System/Core): Hardened, formally verified tools
(kernel-level drivers) operate with high autonomy but
are subject
to continuous runtime audit and anomaly
detection [32].

This tiered approach allows the “USB-C” flexibility for
low-risk experimentation while enforcing “Air Traffic Control”
rigor for enterprise-grade operations.

For organizations adopting MCP, we propose a strategic
roadmap aligned with the defense-in-depth principles analyzed
in this survey.

a) Phase 1: Visibility and containment (Immediate):

Organizations must treat MCP servers as ”shadow IT.” The
immediate priority is discovery and cataloging. Security teams
should enforce policy-based gateways that log all tool in-
vocations and block known-bad tool definitions. Adoption
of basic prompt filters (OWASP LLM01 mitigation) and
requiring ”human-in-the-loop” for all state-changing actions
(POST/DELETE/UPDATE) is the baseline requirement [36].
b) Phase 2: Zero Trust Architecture (Mid-Term): Move
from implicit
the
ETDI framework to enforce tool signatures and immutable
versioning [6]. Deploy Identity-Aware Proxies that bind every
MCP request to a specific user identity, ensuring that an agent
cannot escalate privileges beyond the user who invoked it
(solving the Confused Deputy problem) [8].

to explicit verification. Implement

trust

c) Phase 3: Automated Governance (Long-Term):

Implement ”Governance-as-Code.” Policies regarding data
sovereignty (e.g., ”No PII in external context”) should be en-
forced by the protocol layer itself, using sidecar monitors that
inspect semantic payloads in real-time [42]. At this stage, or-
ganizations should integrate ”Watchdog Agents”—specialized,
small models trained solely to detect alignment failures in
larger agents—to act as automated circuit breakers [41].

Ultimately, the future of MCP lies in normalizing these
security practices. Just as TLS became the invisible default
for web traffic, cryptographic provenance and semantic sand-
boxing must become the invisible default for Agentic AI. Only
then can we safely harness the immense potential of connected
intelligence.

X. CONCLUSION

The Model Context Protocol (MCP) represents a water-
shed moment
in the history of Artificial Intelligence. By
standardizing the interface between probabilistic models and
deterministic systems, it solves the fragmentation that has long
hindered the deployment of truly useful, agentic AI. However,
as this survey has detailed, the very features that make MCP
powerful—its modularity, context-awareness, and capability to
execute tools—also introduce a profound new spectrum of
risks that straddle the traditional boundary between cyberse-
curity and AI safety.

Through our systematization of knowledge, we have demon-
strated that the MCP ecosystem cannot be secured by treating
it merely as an API or merely as an LLM. The unique
coupling of Context (Resources) and Action (Tools) creates
a ”semantic attack surface” where threats like Indirect Prompt
Injection can escalate into real-world operational damage, and
where epistemic failures (hallucinations) can result in security
breaches. We have shown that existing defenses are necessary
but insufficient; securing MCP requires a new architectural
paradigm that includes cryptographic provenance [6], runtime

intent verification [32], and rigorous, capability-based isolation
[37].

As we look to the future, the responsibility for securing this
ecosystem is shared. Protocol designers must bake identity and
verification into the core specification; tool developers must
adopt ”secure-by-design” principles that treat model inputs as
untrusted user data; and organizations must evolve their gov-
ernance frameworks to monitor agentic behavior continuously.
Ultimately, the Model Context Protocol is poised to become
the connective tissue of the Agentic Web. If the community
can rally to address the security and safety challenges outlined
in this paper, MCP will not only unlock the next generation
of AI capability but will also set the standard for how we
build trustworthy, human-centric autonomous systems. The
path forward is clear: innovation must be matched, step for
step, with rigorous verification and governance.

REFERENCES

[1] Model Context Protocol: Host-Server Communication Specification,
Model Context Protocol Working Group, 2025. [Online]. Available:
https://modelcontextprotocol.io/specification

[2] E. Cross, “The ”s” in MCP stands for security,” Medium, apr 2025,
blog Post. [Online]. Available: https://elenacross7.medium.com/%EF%
B8%8F-the-s-in-mcp-stands-for-security-91407b33ed6b

[3] X. Hou, Y. Zhao, S. Wang, and H. Wang, “Model context
protocol
(MCP): Landscape, security threats, and future research
directions,” arXiv preprint arXiv:2503.23278, 2025. [Online]. Available:
https://arxiv.org/abs/2503.23278

[4] B. Radosevich and J. Halloran, “MCP safety audit: LLMs with the
model context protocol allow major security exploits,” arXiv preprint
arXiv:2504.03767, 2025. [Online]. Available: https://arxiv.org/abs/2504.
03767

[5] Y. Guo, P. Liu, W. Ma, Z. Deng, X. Zhu, P. Di, X. Xiao, and
S. Wen, “Systematic analysis of MCP security,” arXiv preprint
arXiv:2508.12538, 2025. [Online]. Available: https://arxiv.org/abs/2508.
12538

[6] M. Bhatt, V. S. Narajala,

squatting and rug pull attacks

“ETDI: Mitigating
tool
in model context protocol
(MCP),” arXiv preprint arXiv:2506.01333, 2025. [Online]. Available:
https://arxiv.org/abs/2506.01333

and I. Habler,

[7] H. Bui, P. Li, and I. M. Zafar, “gvisor: A user-space kernel for container

sandbox isolation,” Google Research, Tech. Rep., 2020.

“When AI has

[8] Pomerium,
MCP
Analysis.
when-ai-has-root-lessons-from-the-supabase-mcp-data-leak

from the Supabase
post-Mortem
2025,
https://www.pomerium.com/blog/

root: Lessons
jul

leak,” Pomerium Blog,

[Online]. Available:

data

[9] The ML Architect,

“The
context
(MCP),”
the-architectural-elegance-of-model-context-protocol-mcp/,
accessed: 2025-12-01.

of model
https://themlarchitect.com/blog/
2025,

architectural

elegance

protocol

[10] S. Datta, S. K. Nahin, A. Chhabra, and P. Mohapatra, “Agentic ai
security: Threats, defenses, evaluation, and open challenges,” arXiv
preprint arXiv:2510.23883, 2025.

[11] A. Ehtesham, A. Singh, G. K. Gupta, and S. Kumar, “A survey of
agent interoperability protocols: Model context protocol (mcp), agent
communication protocol (acp), agent-to-agent protocol (a2a), and agent
network protocol (anp),” arXiv preprint arXiv:2505.02279, 2025.
[12] A. D. Piazza, “MCP servers: The new security nightmare,” https:
//equixly.com/blog/2025/03/29/mcp-server-new-security-nightmare/,
2025, equixly Blog.

[13] T. Shapira, “MCP security: Key risks, controls & best practices ex-
plained,” https://www.reco.ai/learn/mcp-security, 2025, reco Security
Guide.

[14] G. Florencio Cano Gabarda, “Model context protocol (MCP): Under-
standing security risks and controls,” https://www.redhat.com/en/blog/
model-context-protocol-mcp-understanding-security-risks-and-controls,
2025, red Hat Blog.

[15] V. S. Narajala and I. Habler, “Enterprise-grade security for

the
model context protocol (MCP): Frameworks and mitigation strategies,”
arXiv preprint arXiv:2504.08623, 2025.
[Online]. Available: https:
//arxiv.org/abs/2504.08623

[16] V. Sauter, “Beyond dos: How unbounded consumption is reshaping LLM
https://www.promptfoo.dev/blog/unbounded-consumption/,

security,”
2024, promptfoo Blog.

[17] D.

Traub,

“Mcp
misconceptions,”

”server”

terminology

dangerous
https://github.com/modelcontextprotocol/

creates

user
modelcontextprotocol/issues/630, 2025, gitHub Issue #630.

[18] L. Beurer-Kellner

and M.

Fischer,

Tool

cation:
poisoning
mcp-security-notification-tool-poisoning-attacks,
Labs Blog.

attacks,”

“Mcp

notifi-
security
https://invariantlabs.ai/blog/
invariant

2025,

[19] “Ai risk management framework (ai rmf 1.0),” National Institute of Stan-
dards and Technology (NIST), Tech. Rep. NIST AI 100-1, 2023. [On-
line]. Available: https://www.nist.gov/itl/ai-risk-management-framework
[20] “Regulation (eu) 2024/1689 of the european parliament and of the
council (eu ai act),” 2024, official Journal of the European Union, L
2024/1689.

[21] OWASP Foundation, “Owasp top 10 for

applications,” 2025, version 2.0.
owasp.org/llmrisk/llm01-prompt-injection/

large language model
[Online]. Available: https://genai.

[22] Y. Gao, Y. Xiong, X. Gao et al., “Retrieval-augmented generation for
large language models: A survey,” arXiv preprint arXiv:2312.10997,
2023.

[23] N. F. Liu, K. Lin, J. Hewitt et al., “Lost in the middle: How language
models use long contexts,” Transactions of the Association for Compu-
tational Linguistics, vol. 12, pp. 157–173, 2024.

[24] IBM,

“Human-in-the-loop

(hitl),”

https://www.ibm.com/topics/

human-in-the-loop, 2024.

[25] K. Greshake, S. Abdelnabi et al., “Not what you’ve signed up for: Com-
promising real-world llm-integrated applications with indirect prompt
injection,” arXiv preprint arXiv:2302.12173, 2023.

[26] J. Leike, D. Krueger, T. Everitt, M. Martic, V. Maini, and S. Legg,
“Scalable agent alignment via reward modeling: a research direction,”
arXiv preprint arXiv:1811.07871, 2018.

[27] K. Holtman, “Agi agent safety by iteratively improving the utility

function,” arXiv preprint arXiv:2007.05411, 2020.

[28] R. Shah, V. Varma, R. Kumar, M. P. Kotary, V. Krakovna, S. Armstrong,
and A. Dragan, “Goal misgeneralization: Why correct specifications
aren’t enough for correct goals,” arXiv preprint arXiv:2210.01790, 2022.
[29] E. Hubinger, C. van Merwijk et al., “Risks from learned optimization in
advanced machine learning systems,” arXiv preprint arXiv:1906.01820,
2019.

[30] “Ai

cybersecurity

U.S. Department
Available:
line].
Library/AI-CybersecurityRMTailoringGuide.pdf

risk

guide,”
of Defense,
[On-
https://dodcio.defense.gov/Portals/0/Documents/

management
Tech.

tailoring

2025.

Rep.,

[31] H. Song, Y. Shen, W. Luo, L. Guo, T. Chen et al., “Beyond the protocol:
Unveiling attack vectors in the model context protocol ecosystem,” arXiv
preprint arXiv:2506.02040, 2025.

[32] Z. Wang et al., “Mindguard: Tracking, detecting, and attributing mcp
tool poisoning attack via decision dependence graph,” arXiv preprint
arXiv:2508.20412, 2025.

[33] G. Ntousakis, “Securing mcp-based agent workflows,” in Proceedings

of PACMI 2025, 2025.

[34] S. Rose, O. Borchert, S. Mitchell, and S. Connelly, “Nist sp 800-207:
Zero trust architecture,” National Institute of Standards and Technology,
Special Publication, 2020.

[35] Z. Wang, J. Zhang et al., “MCPTox: A benchmark for tool poisoning
attack on real-world MCP servers,” Preprint, 2025, available via Re-
searchGate.

[36] OWASP Foundation, “Llm01: Prompt injection,” OWASP Top 10 for

LLM Applications, 2025.

[37] G. Klein, K. Elphinstone, G. Heiser et al., “The sel4 microkernel – an
end-to-end formally verified operating system,” in Proceedings of the
22nd ACM Symposium on Operating Systems Principles (SOSP ’09),
2009.

[38] S. H. Alhazmi, M. I. Alghamdi, A. Aljebali et al., “Survey on secure se-
rialization techniques and deserialization vulnerabilities,” IEEE Access,
vol. 11, 2023.

[39] Z. Zhao, B. Alon, K. Wang et al., “Protocol integrity framework for ai

toolchains,” arXiv preprint arXiv:2505.11872, 2025.

[40] OWASP Foundation, “Llm07: System prompt leakage,” OWASP Top 10

for LLM Applications, 2025.

[41] S. Raza, R. Sapkota, M. Karkee, and C. Emmanouilidis, “Trism for
agentic ai: A review of trust, risk, and security management in llm-
based agentic multi-agent systems,” arXiv preprint arXiv:2506.04133,
2025.

[42] R. F. Del Rosario, K. Krawiecka, and C. Schroeder de Witt, “Ar-
llm agents: A guide to secure plan-then-execute

chitecting resilient
implementations,” arXiv preprint arXiv:2509.08646, 2025.

[43] Y. Gao et al., “Ragguard: Retrieval augmentation with verifiable prove-

nance,” arXiv preprint arXiv:2505.11221, 2025.

[44] Forge Code, “MCP security crisis: Uncovering vulnerabilities and
attack vectors - part 1,” Forge Code Blog, jun 2025, security Guide.
[Online]. Available: https://forgecode.dev/blog/prevent-attacks-on-mcp/
[45] OWASP Foundation, “OWASP LLM security verification standard
(SVS),” Industry Standard Draft, 2024. [Online]. Available: https:
//owasp.org/www-project-llm-verification-standard/

[46] N. Tihanyi, T. Bisztray et al., “Vulnerability detection: From formal
verification to large language models,” arXiv preprint arXiv:2503.10784,
2025.

[47] W. Xing, Z. Qi et al., “MCP-Guard: A defense framework for
model context protocol integrity in LLM applications,” arXiv preprint
arXiv:2508.10991, 2025.

[48] Forge Code, “MCP security prevention: Practical strategies for AI
development - part 2,” Forge Code Blog, 2025, security Guide. [Online].
Available: https://forgecode.dev/blog/prevent-attacks-on-mcp-part2/
[49] H. Huang et al., “LongSafety: Enhance safety for long-context LLMs,”

arXiv preprint arXiv:2411.06899, 2024.

[50] General Analysis, “Supabase MCP can leak your entire SQL database,”
General Analysis Blog, 2024, incident Analysis. [Online]. Available:
https://www.generalanalysis.com/blog/supabase-mcp-blog

[51] C. Clop and Y. Teglia, “Backdoored retrievers

in-
jection attacks on retrieval augmented generation,” arXiv preprint
arXiv:2410.14479, 2024.

for prompt

[52] M. Wu et al., “I know what you asked: Prompt

leakage via
KV-cache sharing in multi-tenant LLM serving,” in Proceedings
(NDSS)
of
Symposium, 2025. [Online]. Available: https://www.ndss-symposium.
org/wp-content/uploads/2025-1772-paper.pdf

System Security

and Distributed

the Network

[53] OWASP Foundation, “LLM08: Vector and embedding weaknesses,”
[Online]. Available: https:

OWASP LLM Top 10 Risk, 2024.
//genai.owasp.org/llmrisk/llm08-excessive-agency/
“LLM vector

flaws

[54] SC Media,
privacy,
Article.
llm-vector-flaws-threaten-data-security-privacy-and-model-integrity

security,
news
https://www.scworld.com/feature/

threaten
SC Media,

and model
[Online].

Available:

integrity,”

2024,

data

[55] Brimlabs,

“Why MCP

is

crucial

LLM applications,”

multi-tenant
architecture Guide.
why-mcp-is-crucial-for-building-multi-user-multi-tenant-llm-applications/

[Online]. Available:

for
Brimlabs

building multi-user,
Blog,
2024,
https://brimlabs.ai/blog/

[56] Amazon Web Services (AWS), “Multi-tenant RAG implementation
with Amazon Bedrock and Amazon OpenSearch service for SaaS using
JWT,” AWS Machine Learning Blog, 2024,
implementation Guide.
[Online]. Available: https://aws.amazon.com/blogs/machine-learning/
multi-tenant-rag-implementation-with-amazon-bedrock-and-amazon-opensearch-service-for-saas-using-jwt/

[57] Javelin,

to

the model

“Javelin launches MCP security to bring defense-in-
layer,” Press Release,
protocol
[Online]. Available:

depth
BusinessWire, 2025,
https://www.businesswire.com/news/home/20250819727553/en/
Javelin-Launches-MCP-Security-to-Bring-DefenseinDepth-to-the-Model-Context-Protocol-Layer

accessed: 2025-12-07.

context

