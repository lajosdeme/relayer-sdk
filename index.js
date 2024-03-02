import UniversalProfileContract from '@lukso/lsp-smart-contracts/artifacts/UniversalProfile.json' assert { type: "json" };
import KeyManagerContract from '@lukso/lsp-smart-contracts/artifacts/LSP6KeyManager.json' assert { type: "json" };
import {
    EIP191Signer
} from '@lukso/eip191-signer.js';
import {
    ethers
} from 'ethers';

import axios from 'axios';

class RelayerSDK {
    constructor(userId, contractAddress, contractAbi, privateKey, provider) {
        this.userId = userId;
        this.contractAddress = contractAddress;
        this.contractAbi = contractAbi;
        this.privateKey = privateKey;
        this.provider = provider;

        this.chainId = "0x0000000000000000000000000000000000000000000000000000000000001069"
        this.validityTimestamps = "0x0000000000000000000000000000000000000000000000000000000067748580";
        this.baseUrl = "http://localhost:3000"
        this.executeEndpoint = "/execute"
        this.LSP25_VERSION = 25
    }

    execute = async function (universalProfileAddress, value, functionName, functionArguments) {
        const data = await this.createData(functionName, functionArguments);

        const abiPayload = await this.createAbiPayload(universalProfileAddress, data, 0);

        const universalProfile = await this.getUniversalProfile(universalProfileAddress);

        const encodedMessage = await this.createEncodedMessage(abiPayload, universalProfile, value);

        const signedMessage = await this.signEncodedMessage(universalProfile, encodedMessage);

        const keyManager = await this.getKeyManager(universalProfile);
        const channelId = 0;
        const controllerAccount = new ethers.Wallet(this.privateKey).connect(
            this.provider,
        );
        const nonce = await keyManager.getNonce(controllerAccount.address, channelId);

        await this.makeAPICall(universalProfileAddress, abiPayload, nonce, signedMessage);
        return signedMessage;
    }

    createData = async function (functionName, functionArguments) {
        const contract = new ethers.Contract(this.contractAddress, this.contractAbi, this.provider);

        const data = contract.interface.encodeFunctionData(functionName, functionArguments);
        console.log("Encoded data:", data);
        return data;
    }

    getUniversalProfile = function (universalProfileAddress) {
        const controllerAccount = new ethers.Wallet(this.privateKey).connect(
            this.provider,
        );

        const universalProfile = new ethers.Contract(
            universalProfileAddress,
            UniversalProfileContract.abi,
            controllerAccount
        );

        return universalProfile;
    }

    getKeyManagerAddress = async function (universalProfile) {
        const keyManagerAddress = await universalProfile.owner();
        return keyManagerAddress;
    }

    getKeyManager = async function (universalProfile) {
        const controllerAccount = new ethers.Wallet(this.privateKey).connect(
            this.provider,
        );

        const keyManagerAddress = await universalProfile.owner();
        const keyManager = new ethers.Contract(
            keyManagerAddress,
            KeyManagerContract.abi,
            controllerAccount
        );

        return keyManager;
    }

    createAbiPayload = async function (universalProfileAddress, data, value) {
        const universalProfile = this.getUniversalProfile(universalProfileAddress);

        const abiPayload = universalProfile.interface.encodeFunctionData('execute', [
            0, // Operation type: CALL
            this.contractAddress,
            value,
            data, // Data
        ]);

        console.log("Encoded payload: ", abiPayload);

        return abiPayload;
    }

    createEncodedMessage = async function (abiPayload, universalProfile, msgValue) {
        const controllerAccount = new ethers.Wallet(this.privateKey).connect(
            this.provider,
        );

        const keyManager = await this.getKeyManager(universalProfile);

        const channelId = 0;
        const nonce = await keyManager.getNonce(controllerAccount.address, channelId);
        console.log("NONCE: ", nonce.toString())

        let encodedMessage = ethers.utils.solidityPack(
            ['uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'bytes'],
            [
                // MUST be number `25`
                this.LSP25_VERSION, // `0x0000000000000000000000000000000000000000000000000000000000000019`
                // e.g: `4201` for LUKSO Testnet
                this.chainId, // `0x0000000000000000000000000000000000000000000000000000000000001069`
                // e.g: nonce number 5 of the signer key X 
                // (the private key associated with the address of the controller that want to execute the payload)
                nonce, // `0x0000000000000000000000000000000000000000000000000000000000000005`
                // e.g: valid until 1st January 2025 at midnight (GMT).
                // Timestamp = 1735689600
                this.validityTimestamps, // `0x0000000000000000000000000000000000000000000000000000000067748580`
                // e.g: not funding the contract with any LYX (0)
                msgValue, // `0x0000000000000000000000000000000000000000000000000000000000000000`
                // e.g: execute(uint256,address,uint256,bytes) -> send 3 LYX to address `0xcafecafecafecafeafecafecafecafeafecafecafecafeafecafecafecafe`
                abiPayload, // `0x44c028fe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cafecafecafecafecafecafecafecafecafecafe00000000000000000000000000000000000000000000000029a2241af62c000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000`
            ],
        );

        return encodedMessage;
    }

    signEncodedMessage = async function (universalProfile, encodedMessage) {
        const keyManagerAddress = await this.getKeyManagerAddress(universalProfile);
        let eip191Signer = new EIP191Signer();

        let {
            signature
        } = eip191Signer.signDataWithIntendedValidator(
            keyManagerAddress,
            encodedMessage,
            this.privateKey,
        );

        return signature;
    }

    makeAPICall = async function (universalProfileAddress, abi, nonce, signedMessage) {
        const url = this.baseUrl + this.executeEndpoint;
        const input = {
            "user_id": this.userId,
            "address": universalProfileAddress,
            "transaction": {
                "abi": abi,
                "nonce": `${nonce}`,
                "signature": signedMessage,
                "validityTimestamps": this.validityTimestamps,
            }
        }

        try {
            const response = await axios.post(url, input);
            return response;
        } catch (error) {
            return error;
        }
    }
}

export default RelayerSDK