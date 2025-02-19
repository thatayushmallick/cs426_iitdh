// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.4.26;
contract MyContract {
   uint amount;
   uint value;

   constructor () public  {
      amount = 0;
      value = 100;
   }
   function getBalance() public view returns(uint) {
      return value;
   }
   function getAmount() public view returns(uint) {
      return amount;
   }
   function send(uint newDeposit) public {
      value = value - newDeposit;
      amount = amount + newDeposit;
   }
}

