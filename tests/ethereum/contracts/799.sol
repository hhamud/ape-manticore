//SPDX-License-Identifier: MIT
contract X { function X(address x) {} }
contract C { function C(address x) { new X(x); } }
