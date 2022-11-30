//SPDX-License-Identifier: MIT
contract Simple {
    function f(uint a) payable public {
        if (a == 65) {
            revert();
        }
    }
}
