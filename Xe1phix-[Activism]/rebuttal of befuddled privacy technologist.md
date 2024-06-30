

Rebuttal of "[36C3] The ecosystem is moving"
============================================


abstract
--------

Moxie is wrong about a lot of things in this talk. Here I'll discuss
my rebuttals and of course I will provide plenty of useful information
and informative citations which you can follow up on.

To be clear I am responding to the recording of Moxie's talk although I heard
he did not wish it to be recorded, nevertheless it is extremely important
to debunk the myriad of falsehoods presented in his talk:

https://tube.ksl-bmx.de/videos/watch/12be5396-2a25-4ec8-a92a-674b1cb6b270

Although there is a hacker-news discussion about this talk:

https://news.ycombinator.com/item?id=21904041

My feeling is that the past forty years of academic literature on
anonymous communication networks are not adequately represented in
this public discussion.


a brief introduction to decentralized systems
---------------------------------------------

What we really mean by decentralized systems is a system which
provides assurances which are dependent on multiple security domains.
However there are obviously possible decentralized system designs
which grant each security domain the full authority of the system; in
computer science this is known as "ambient authority" and it is of
course not a desireable property. Least authority or least privilege
on the other hand is the design property where each security domain
has the least amount of privilege necessary to perform it's task or
function. [SECNOTSEP]_ This design principle has been applied to
programming language design, operating system design, program design
and decentralized system design. [MARKMTHESIS]_


a brief introduction to anonymous communication networks
--------------------------------------------------------

The academic research into so called metadata protection started
with David Chaum's 1979 paper also published as his 1981 PHD thesis
entitled: "Untraceable electronic mail, return addresses, and digital pseudonyms"
[CHAUM81]_. In the abstract of this paper Chaum states:

"A technique based on public key cryptography is presented that allows an
electronic mail system to hide who a participant communicates with as
well as the content of the communication--in spite of an unsecured
underlying telecommunication system. The technique does not require a
universally trusted authority.  "

Not requiring a universally trusted authority essentially means not
depending on a single security domain. This implies that the system
will have multiple security domains. Later on in Chaum's paper he says:

"The use of a cascade, or series of mixes, offers the advantage that
any single constituent mix is able to provide the secrecy of the
correspondence between the inputs and the outputs of the entire
cascade."

This concept is later reiterated by Byron Ford et al in their
[ANYTRUST]_ paper where they state:

"Anytrust is a decentralized client/server network model, in which each
of many clients—representing group members—trust only that at least
one of a smaller but diverse set of “servers” or “super-peers” behaves
honestly, but clients need not know which server to trust."

Another way to state this concept in terms of mix networks is to say:
There must be at least one honest mix in the mix network routes used.
This more flexible definition allows for various topologies besides a cascade.
Claudia Diaz et al discuss the benefits of the stratified topology in their
paper. [MIXTOPO10]_

In terms of the principles of least authority, a mixnet with only one
mix implies a mix which has excess authority. This single mix has the
authority to link input and output messages whereas this is not the case
if there are multiple mixes in each route where each mix is operated by
a different entity, thus using multiple security domains.

There are of course many other decentralized models which also avoid
deep pockets of excess authority. For example some multi party computation
based systems can withstand up to one third of the nodes becoming
compromised.

Anonymous communication networks offer users metadata protections which are
formally known as privacy notions and the best and latest paper on the subject is:
On Privacy Notions in Anonymous Communication [PRIVNOTIONS]_



citations
---------

.. [SECNOTSEP]
The Structure of Authority: Why Security Is not a Separable Concern
by Mark S. Miller, Bill Tulloh, and Jonathan S. Shapiro
http://www.erights.org/talks/no-sep/secnotsep.pdf

.. [MARKMTHESIS]
Robust Composition:
Towards a Unified Approach to Access Control and Concurrency Control
May 2006
by Mark Samuel Miller
http://erights.org/talks/thesis/markm-thesis.pdf

.. [CHAUM81]
Untraceable electronic mail, return addresses, and digital pseudonyms
February 1981
by David Chaum
https://www.freehaven.net/anonbib/cache/chaum-mix.pdf

.. [ANYTRUST]
Scalable Anonymous Group Communication in the Anytrust Model
by David Isaac Wolinsky, Henry Corrigan-Gibbs, Bryan Ford and, Aaron Johnson
https://www.ohmygodel.com/publications/d3-eurosec12.pdf

.. [MIXTOPO10]
"Impact of Network Topology on Anonymity
and Overhead in Low-Latency Anonymity Networks", PETS, July 2010,
Diaz, C., Murdoch, S., Troncoso, C.
https://www.esat.kuleuven.be/cosic/publications/article-1230.pdf

.. [PRIVNOTIONS]
On Privacy Notions in Anonymous Communication
by Christiane Kuhn, Martin Beck, Stefan Schiffner, Eduard Jorswieck, Thorsten Strufe
https://arxiv.org/abs/1812.05638
