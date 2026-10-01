// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * syntax-zoo — one minimal function per Solidity construct that the R4.1 CFG
 * builder must lower.
 *
 * Purpose: the real benchmark corpus contains these constructs scattered
 * across large files, so a lowering gap shows up as thousands of diffs whose
 * root cause is ambiguous. Here each construct is isolated, so a red function
 * names its own missing lowering rule. Add a case per construct as the builder
 * grows; the differential gate is per-repo, so closing one function at a time
 * is directly measurable.
 *
 * Constructs covered here:
 *   ifCase / elseCase ....... if / else, if-else-if chains
 *   forCase .................. for with init/cond/post
 *   whileCase ................ while loop
 *   doWhileCase .............. do-while loop
 *   breakCase / continueCase . break and continue out of nested loops
 *   uncheckedCase ............ unchecked block
 *   tryCase .................. try/catch with a reverting external call
 *   modifierCase ............. modifier application (body NOT inlined)
 *   tupleDeclCase ............ tuple variable declaration + assignment
 *   namedReturnCase .......... named return parameters (implicit return)
 *   compoundAssignCase ....... += -= *= /= and ++/-- in expression position
 */
contract SyntaxZoo {
    uint256 public counter;
    address public owner = msg.sender;
    bool internal unlocked;

    event Jumped(uint256 value);

    modifier onlyPositive(uint256 v) {
        require(v > 0, "non-positive");
        _;
    }

    function ifCase(bool a, bool b) public pure returns (bool) {
        if (a) {
            return true;
        } else if (b) {
            return false;
        } else {
            return a && b;
        }
    }

    function forCase(uint256 n) public returns (uint256 sum) {
        for (uint256 i = 0; i < n; i++) {
            sum += i;
        }
    }

    function whileCase(uint256 n) public returns (uint256 acc) {
        uint256 i;
        while (i < n) {
            acc += i;
            i++;
        }
    }

    function doWhileCase(uint256 n) public returns (uint256 acc) {
        uint256 i;
        do {
            acc += i;
            i++;
        } while (i < n);
    }

    function breakCase(uint256 n) public returns (uint256) {
        uint256 acc;
        for (uint256 i = 0; i < n; i++) {
            if (i == 3) {
                break;
            }
            acc += i;
        }
        return acc;
    }

    function continueCase(uint256 n) public returns (uint256 acc) {
        for (uint256 i = 0; i < n; i++) {
            if (i % 2 == 0) {
                continue;
            }
            acc += i;
        }
    }

    function uncheckedCase(uint256 x) public pure returns (uint256 y) {
        unchecked {
            y = x + 1;
        }
    }

    function tryCase(address target, bytes calldata payload) public returns (bool ok) {
        try ISyntaxZooCallee(target).probe(payload) {
            ok = true;
        } catch Error(string memory reason) {
            emit Jumped(bytes(reason).length);
            ok = false;
        } catch {
            ok = false;
        }
    }

    function modifierCase(uint256 v) public onlyPositive(v) returns (uint256) {
        counter = v;
        return counter;
    }

    function tupleDeclCase() public returns (uint256 a, uint256 b) {
        (uint256 x, uint256 y) = (1, 2);
        a = x;
        b = y;
    }

    function namedReturnCase(uint256 v) public returns (uint256 doubled, uint256 tripled) {
        doubled = v * 2;
        tripled = v * 3;
    }

    function compoundAssignCase(uint256 v) public returns (uint256) {
        uint256 acc = v;
        acc += 1;
        acc -= 2;
        acc *= 3;
        acc /= 4;
        acc++;
        --acc;
        return acc;
    }
}

interface ISyntaxZooCallee {
    function probe(bytes calldata payload) external returns (bytes32);
}