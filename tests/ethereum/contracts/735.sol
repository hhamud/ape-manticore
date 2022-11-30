//SPDX-License-Identifier: MIT
contract SS {
    address recvr;
    function setme() {
        recvr = msg.sender;
    }
    function sui() {
        suicide(recvr);
    }
}
