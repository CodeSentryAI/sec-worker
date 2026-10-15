# ERC-20 v1 ABI screen scope

The first ERC-20 screen is intentionally limited to one property:

> For an explicitly selected concrete contract with no fallback or constructor
> assembly, the compiler ABI must expose the six mandatory ERC-20 function
> signatures with the specified return types.

The mandatory functions are `totalSupply() -> uint256`,
`balanceOf(address) -> uint256`, `transfer(address,uint256) -> bool`,
`transferFrom(address,address,uint256) -> bool`,
`approve(address,uint256) -> bool`, and
`allowance(address,address) -> uint256`.

The verifier is pinned to the [ERC-20 specification](https://eips.ethereum.org/EIPS/eip-20).
`name`, `symbol`, and `decimals` are optional under that specification and are
not required by this rule.

## Trust behavior

- Missing mandatory function signatures are `verified` only when the normal
  `sec-detect` path performs a successful controlled Standard JSON compile and
  retains the exact input/output artifacts and compiler identity. The evidence
  includes SHA-256 references for the input, output, and copied compiler binary.
- The Verified scope requires matching complete source path sets, a successful
  solc run, target and C3 ancestor AST identities, and no constructor with
  inline assembly. A fallback in the target or any ancestor makes the result
  indeterminate because it can dispatch selectors absent from the ABI.
- Direct calls to the pure `checkErc20Abi` library function still emit Signals;
  only `runErc20AbiCompile` can attach compiler-run provenance and promote
  missing function entries.
- Missing or mis-shaped `Transfer` and `Approval` ABI declarations are
  `signal` findings. The contract may still emit the required logs directly,
  so ABI absence alone does not prove behavioral noncompliance.
- Abstract implementations are not evaluated. Interface declarations can be
  checked because the rule concerns ABI shape only.
- A clean ABI result does **not** verify ERC-20 behavior. It says nothing about
  balances, allowances, return values at runtime, zero-value transfers,
  emitted logs, reverts, or authorization.
- Findings retain compiler ABI and source content JSON pointers. Run-scoped raw
  Standard JSON input/output, version output, and a provenance JSON file are
  retained next to the scan report. The source tree is compiled as one bundle;
  framework-specific remappings and build settings are not inferred yet, so a
  project that needs them will fail closed rather than produce a result.

## Explicit non-goals

This rule does not claim complete ERC-20 conformance, test execution, proxy
behavior, or gas savings. Those require separate validators and evidence.
