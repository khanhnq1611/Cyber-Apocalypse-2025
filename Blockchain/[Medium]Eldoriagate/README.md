## Source code
First of all, we should understand the source code clearly.
``Setup.sol``
```C#
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

import { EldoriaGate } from "./EldoriaGate.sol";

contract Setup {
    EldoriaGate public TARGET;
    address public player;

    event DeployedTarget(address at);

    constructor(bytes4 _secret, address _player) {
        TARGET = new EldoriaGate(_secret);
        player = _player;
        emit DeployedTarget(address(TARGET));
    }

    function isSolved() public returns (bool) {
        return TARGET.checkUsurper(player);
    }
}
```
``EldoriaGateKernel.sol``
```C#
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

contract EldoriaGateKernel {
    bytes4 private eldoriaSecret;
    mapping(address => Villager) public villagers;
    address public frontend;

    uint8 public constant ROLE_SERF     = 1 << 0;
    uint8 public constant ROLE_PEASANT  = 1 << 1;
    uint8 public constant ROLE_ARTISAN  = 1 << 2;
    uint8 public constant ROLE_MERCHANT = 1 << 3;
    uint8 public constant ROLE_KNIGHT   = 1 << 4;
    uint8 public constant ROLE_BARON    = 1 << 5;
    uint8 public constant ROLE_EARL     = 1 << 6;
    uint8 public constant ROLE_DUKE     = 1 << 7;
    
    struct Villager {
        uint id;
        bool authenticated;
        uint8 roles;
    }

    constructor(bytes4 _secret) {
        eldoriaSecret = _secret;
        frontend = msg.sender;
    }

    modifier onlyFrontend() {
        assembly {
            if iszero(eq(caller(), sload(frontend.slot))) {
                revert(0, 0)
            }
        }
        _;
    }

    function authenticate(address _unknown, bytes4 _passphrase) external onlyFrontend returns (bool auth) {
        assembly {
            let secret := sload(eldoriaSecret.slot)            
            auth := eq(shr(224, _passphrase), secret)
            mstore(0x80, auth)
            
            mstore(0x00, _unknown)
            mstore(0x20, villagers.slot)
            let villagerSlot := keccak256(0x00, 0x40)
            
            let packed := sload(add(villagerSlot, 1))
            auth := mload(0x80)
            let newPacked := or(and(packed, not(0xff)), auth)
            sstore(add(villagerSlot, 1), newPacked)
        }
    }

    function evaluateIdentity(address _unknown, uint8 _contribution) external onlyFrontend returns (uint id, uint8 roles) {
        assembly {
            mstore(0x00, _unknown)
            mstore(0x20, villagers.slot)
            let villagerSlot := keccak256(0x00, 0x40)

            mstore(0x00, _unknown)
            id := keccak256(0x00, 0x20)
            sstore(villagerSlot, id)

            let storedPacked := sload(add(villagerSlot, 1))
            let storedAuth := and(storedPacked, 0xff)
            if iszero(storedAuth) { revert(0, 0) }

            let defaultRolesMask := ROLE_SERF
            roles := add(defaultRolesMask, _contribution)
            if lt(roles, defaultRolesMask) { revert(0, 0) }

            let packed := or(storedAuth, shl(8, roles))
            sstore(add(villagerSlot, 1), packed)
        }
    }

    function hasRole(address _villager, uint8 _role) external view returns (bool hasRoleFlag) {
        assembly {
            mstore(0x0, _villager)
            mstore(0x20, villagers.slot)
            let villagerSlot := keccak256(0x0, 0x40)
        
            let packed := sload(add(villagerSlot, 1))
            let roles := and(shr(8, packed), 0xff)
            hasRoleFlag := gt(and(roles, _role), 0)
        }
    }
}
```
``EldoriaGate.sol``
```C#
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

/***
    Malakar 1b:22-28, Tales from Eldoria - Eldoria Gates
  
    "In ages past, where Eldoria's glory shone,
     Ancient gates stand, where shadows turn to dust.
     Only the proven, with deeds and might,
     May join Eldoria's hallowed, guiding light.
     Through strict trials, and offerings made,
     Eldoria's glory, is thus displayed."
  
                   ELDORIA GATES
             *_   _   _   _   _   _ *
     ^       | `_' `-' `_' `-' `_' `|       ^
     |       |                      |       |
     |  (*)  |     .___________     |  \^/  |
     | _<#>_ |    //           \    | _(#)_ |
    o+o \ / \0    ||   =====   ||   0/ \ / (=)
     0'\ ^ /\/    ||           ||   \/\ ^ /`0
       /_^_\ |    ||    ---    ||   | /_^_\
       || || |    ||           ||   | || ||
       d|_|b_T____||___________||___T_d|_|b
  
***/

import { EldoriaGateKernel } from "./EldoriaGateKernel.sol";

contract EldoriaGate {
    EldoriaGateKernel public kernel;

    event VillagerEntered(address villager, uint id, bool authenticated, string[] roles);
    event UsurperDetected(address villager, uint id, string alertMessage);
    
    struct Villager {
        uint id;
        bool authenticated;
        uint8 roles;
    }

    constructor(bytes4 _secret) {
        kernel = new EldoriaGateKernel(_secret);
    }

    function enter(bytes4 passphrase) external payable {
        bool isAuthenticated = kernel.authenticate(msg.sender, passphrase);
        require(isAuthenticated, "Authentication failed");

        uint8 contribution = uint8(msg.value);        
        (uint villagerId, uint8 assignedRolesBitMask) = kernel.evaluateIdentity(msg.sender, contribution);
        string[] memory roles = getVillagerRoles(msg.sender);
        
        emit VillagerEntered(msg.sender, villagerId, isAuthenticated, roles);
    }

    function getVillagerRoles(address _villager) public view returns (string[] memory) {
        string[8] memory roleNames = [
            "SERF", 
            "PEASANT", 
            "ARTISAN", 
            "MERCHANT", 
            "KNIGHT", 
            "BARON", 
            "EARL", 
            "DUKE"
        ];

        (, , uint8 rolesBitMask) = kernel.villagers(_villager);

        uint8 count = 0;
        for (uint8 i = 0; i < 8; i++) {
            if ((rolesBitMask & (1 << i)) != 0) {
                count++;
            }
        }

        string[] memory foundRoles = new string[](count);
        uint8 index = 0;
        for (uint8 i = 0; i < 8; i++) {
            uint8 roleBit = uint8(1) << i; 
            if (kernel.hasRole(_villager, roleBit)) {
                foundRoles[index] = roleNames[i];
                index++;
            }
        }

        return foundRoles;
    }

    function checkUsurper(address _villager) external returns (bool) {
        (uint id, bool authenticated , uint8 rolesBitMask) = kernel.villagers(_villager);
        bool isUsurper = authenticated && (rolesBitMask == 0);
        emit UsurperDetected(
            _villager,
            id,
            "Intrusion to benefit from Eldoria, without society responsibilities, without suspicions, via gate breach."
        );
        return isUsurper;
    }
}
```
## Summarize the source code
To achieve the Usurper status in the EldoriaGate.sol, you must satisfy two key conditions in the EldoriaGateKernel contract:

#### Condition 1: authenticated = true

How to Activate:

Call the enter function of EldoriaGate with the correct passphrase (the eldoriaSecret stored in EldoriaGateKernel).
This passphrase is located in the last 4 bytes of storage slot 0 in EldoriaGateKernel (not the first 4 bytes).

#### Condition 2: rolesBitMask = 0
How to Activate:
```
Send 255 wei when calling enter.
The msg.value (255 wei) is cast to uint8 → _contribution = 255.
Inside evaluateIdentity, the calculation logic is:
roles = defaultRolesMask (1) + _contribution (255) = 256
Since roles is a uint8, the value 256 overflows → roles = 0.
Note: The assembly check lt(roles, defaultRolesMask) uses 256-bit integers, so 256 > 1 → no revert.
```

Now, we need to understand where the secret is stored. The EldoriaGateKernel’s constructor takes a bytes4 _secret and stores it in eldoriaSecret. In Solidity, state variables are stored in slots.
```bash
khanh@ubuntu:~/Documents/WorkSpaceHTB/HTBCTF/block-chain/blockchain_eldoriagate$ python3 exploit.py 
Kernel address: 0x89dE1bb7fA3244Ee0826DB1B760907E712142026
Full secret storage (32 bytes): 0x00000000000000000000000000000000000000000000000000000000deadfade
Retrieved secret (bytes4): 0x00000000
Transaction hash: 0452291c4917cc898f4e4d406c16b209348bfd7b5b59d995317ae206e56899b4
Transaction status: Failed
Villager data: id=0, authenticated=False, roles=0
Solved: False
```
First time I ran, I though the secret is in the first 4 bytes, so the script was failed.

In Solidity, when a variable is less than 32 bytes, it’s stored right-aligned (padded on the left). 

For example, a bytes4 in slot 0 would occupy the last 4 bytes of the 32-byte slot. 

So when we retrieve slot 0, the bytes4 would be the last 4 bytes of the 32-byte value. And that is 0xdeadfade.

Second, let’s look at the assembly code again:

In ``evaluateIdentity()``:
```C#
let defaultRolesMask := ROLE_SERF
roles := add(defaultRolesMask, _contribution)
if lt(roles, defaultRolesMask) { revert(0, 0) }
Here, defaultRolesMask is ROLE_SERF, which is 1.
```
The _contribution is uint8, so when added to 1, if _contribution is 255, roles becomes 256.

In the assembly statement if ``lt(roles, defaultRolesMask) { revert(0, 0) }``, the values ​​of roles and defaultRolesMask are handled as 256-bit integers (not uint8) and it is 256 > 1. 
We will bypass if condition, roles is not less then defaultRolesMask, and it will not revert.

We achieve the Usurper status with roles = 0 in uint8.

So the correct way is :

1. Retrieve the correct secret from storage slot 0 of the kernel. 
   The secret is the last 4 bytes of the 32-byte slot value.

2. Use this secret to call enter with the correct passphrase.

3. Send 255 wei as msg.value, which leads to contribution = 255.
   Adding 1 (ROLE_SERF) gives 256 in assembly (which is 0 when stored as uint8).
   Since 256 > 1, the check passes, roles is 0. 
   Thus, authenticated is true, roles is 0 → checkUsurper returns true.

An integer overflow, resulting in a rolesBitMask of 0 without
reverting the transaction.
## Exploitation
First, using netcat to the server and get the target’s information.

![image](https://github.com/user-attachments/assets/c93f9e1a-7407-4aa7-aee5-a92ae02223bf)


Full code ``exploit.py``

And when the output is true, access the netcat again and choose option 3 to get the flag.
![image](https://github.com/user-attachments/assets/5e3f19db-cac4-455c-b7d1-fa1615fa8099)

