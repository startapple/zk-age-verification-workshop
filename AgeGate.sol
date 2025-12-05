// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./verifier.sol";

contract AgeGate {
    Verifier public verifier;

    event AccessGranted(address indexed user);

    constructor(address _verifier) {
        verifier = Verifier(_verifier);
    }

    // Passiamo tutti i valori "piatti" come uint, niente array/tuple nested
    function enter(
        uint a0,
        uint a1,
        uint b00,
        uint b01,
        uint b10,
        uint b11,
        uint c0,
        uint c1,
        uint currentYear,
        uint ok
    ) external {
        // Ricostruiamo la struct Proof che si aspetta il Verifier
        Verifier.Proof memory proof = Verifier.Proof(
            Pairing.G1Point(a0, a1),
            Pairing.G2Point(
                [b00, b01],
                [b10, b11]
            ),
            Pairing.G1Point(c0, c1)
        );

        // Prepariamo l'array di input per il Verifier
        uint[2] memory input;
        input[0] = currentYear; // = 2025 nel tuo caso
        input[1] = ok;          // = 1 se age >= 18

        // 1) Verifica crittografica della proof
        require(verifier.verifyTx(proof, input), "Invalid ZK proof");

        // 2) Controllo logico sul risultato del circuito
        require(ok == 1, "User is not >= 18");

        emit AccessGranted(msg.sender);
    }
}