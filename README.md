# SOCKS5 lec

## Structure

`basic.rs` implements a minimal SOCKS5 proxy. It supports the “no authentication” method, the CONNECT command, and all address types (ATYP). It does not support any additional authentication methods or command codes. `advanced.rs` extends basic.rs by adding RFC 1929 (username/password) authentication.

## Things to consider

Both files implement the functionality necessary to operate as a conformant SOCKS5 proxy, and this has been verified in the following environment: Ubuntu (server) and Firefox on Windows 11 (client). For instructional use, however, the files should serve as templates; certain functions (e.g., fn read_request()) should be left unimplemented and completed by students to reinforce their understanding of the RFC.

At present, I am uncertain about the appropriate difficulty level, as I have not yet reviewed any application materials. With guidance from subject-matter experts, I would like to determine which functions should be completed by students. If refactoring is required, I will address it promptly.

## Plan

Looking ahead a three-hour lecture, I propose the following schedule and content plan. I would be grateful for any advice regarding this outline.

- 40-50 minutes: a classroom-based overview of RFC fundamentals
- 130 minutes: hands-on exercises
    - Introduction to RFC 1928
    - Method negotiation
    - Request parsing and validation
    - CONNECT request and successful response flow
    - Packet capture and analysis with Wireshark
    - (Optional) Advanced implementation of RFC 1929