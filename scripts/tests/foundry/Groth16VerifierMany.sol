// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 10372138525701480928860828766419463956498637478160231805145395574781885288380;
    uint256 constant alphay  = 13176121797780159880597940750523786516210346346966263068359760848781991102206;
    uint256 constant betax1  = 15306250380282854696442645657553435917603304245302414048264779912545117344913;
    uint256 constant betax2  = 17560704559444999689636566143981255520386307043161881437149974695667995900532;
    uint256 constant betay1  = 128607358822629690450813818416978740873428963096177594067230292530274904608;
    uint256 constant betay2  = 673795618202544867608139029878371979491436150345238584223051956713284923883;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 16265374339328917885004352178525584857824167892175318266401901883348164420361;
    uint256 constant deltax2 = 15825413634500603312340758432534154322324725383393913730238168854324095526671;
    uint256 constant deltay1 = 11640482329935346301130902529685810547599753431537011782297278937410599774482;
    uint256 constant deltay2 = 11120392805389389312459956572952012095640524807388128440345651559110769090580;

    
    uint256 constant IC0x = 20032792556868417413026701815640598307261234593444435550473871393320194770245;
    uint256 constant IC0y = 3836225919975622607651932697237916483775193417997621819875960769744242046799;
    
    uint256 constant IC1x = 9520834162170739588778827505633566278102912932245679008589750113527746664450;
    uint256 constant IC1y = 1968101715962714282035159065066840481611063926100867468335369295586152329910;
    
    uint256 constant IC2x = 19783783175254848224093423801649285087111351791009220100163400172660144313633;
    uint256 constant IC2y = 12305429983266192893476231291182286727882558000826979659458077565363124998421;
    
    uint256 constant IC3x = 18035768117267901226337219625881587641845170408106461327467513001294315345853;
    uint256 constant IC3y = 16622770975865011254124092038369068068136383549647849118790942379449735464203;
    
    uint256 constant IC4x = 18273742159942774452623263317338799336262102907401277550531258335446749427225;
    uint256 constant IC4y = 9111382491233630477457420580336206272903014255022555091684614507793447420465;
    
    uint256 constant IC5x = 20478430997438103505261439138617227838119878161508527861290370465734605203961;
    uint256 constant IC5y = 10678913471957573821420388963468765120772344490033007875341069454643282856524;
    
    uint256 constant IC6x = 9356555957995431794602993498244828340420980836780185716652402478217453206902;
    uint256 constant IC6y = 17289492827124008737960108899640482010134141248461010584675618012744678525268;
    
    uint256 constant IC7x = 4762746757026137436089147747713758677027916546811269353179487946374981852711;
    uint256 constant IC7y = 2309528997499396323451126038494562046847078604476306079755016603426654798209;
    
    uint256 constant IC8x = 7609813366369934532768731040075543344340563456655933093624669940689751521681;
    uint256 constant IC8y = 2930959926451582052292408653710922747283200038466552742587384382008247538846;
    
    uint256 constant IC9x = 16463932498730620277037005772712435199474243924425581454919063027830688526345;
    uint256 constant IC9y = 13730280945150617347804244162102249009926728284180430853887217001988664037126;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[9] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
