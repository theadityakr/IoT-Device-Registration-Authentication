// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.9.0;

    enum PermissionLevel {
        None,
        Owner,
        TA,
        Peer
    }

    struct Authority {
        address entity;
        PermissionLevel permission ;
    }

    struct DeviceInfo {
        address deviceId;
        address owner;
        address[] deviceOwnershipTrace;

    }

    struct DeviceCRP {
        uint256 chalHash;
        uint256 respHash;
    }

    struct IPFS{
        address deviceId;
        string  ipfschalCID;
        string  ipfsrespCID;
    }

contract DeviceRegistry {
    address private ownerAddress;
    mapping(address => Authority) private peoples;
    mapping(address => DeviceInfo) private devicesinfo;
    mapping(address => mapping(uint256 => DeviceCRP)) private devicescrp;
    mapping(address => IPFS) private ipfsfiles;


    constructor() {
        ownerAddress = msg.sender;
        peoples[ownerAddress] = Authority({entity :ownerAddress,permission : PermissionLevel.Owner});
    }

    // Debuging Functions
    // function getPeople(address entity) public view returns(Authority memory){ return peoples[entity]; }
    // function getCurrentSender() public view returns(Authority memory){ return peoples[msg.sender];}
    // function getDeviceInfo(address entity) public view returns (DeviceInfo memory) { return devicesinfo[entity]; }
    // function getDeviceCRP(address entity,uint256 chalHash) public view returns (DeviceCRP memory) { return devicescrp[entity][chalHash]; }


    function getAuthority(address entity) private view returns (PermissionLevel)  {
        return peoples[entity].permission;
    }

    // 0x26c591Fc46d702Db17D422ef0827F255941D6f39
    function addNode(address tanode) public {
        PermissionLevel x = getAuthority(msg.sender);
        if (getAuthority(msg.sender) != PermissionLevel.Owner && x != PermissionLevel.TA) {
            revert("Sender doesn't have permission to add TA Node.");
        }
        peoples[tanode] = Authority({entity :tanode,permission : PermissionLevel.TA});
    }

    // 0x3Fc25b223768Ae2a3e56D1a22c31b04B6a745e93
    function addPeer(address peer) public {
       PermissionLevel x = getAuthority(msg.sender);
        if (x != PermissionLevel.Owner && x != PermissionLevel.TA) {
             revert("Sender doesn't have permission to add Peer Node.");
        }
        peoples[peer] = Authority({entity :peer,permission : PermissionLevel.Peer});
    }

    // 0xC91E862338272667dc4dad2C306D924f59A53480,0x3e0329E19dc43A31313f6a923DFD99aFe11AE3A1,0000,1111
    function registerDevice(address deviceId,address owner,uint256 chalHash,uint256 respHash) public {

        PermissionLevel x = getAuthority(msg.sender);
         if (x != PermissionLevel.Owner && x != PermissionLevel.TA) {
            revert("Sender doesn't have permission to Register Device.");
        }

        DeviceCRP storage device2 = devicescrp[deviceId][chalHash];
        if (device2.chalHash == chalHash) revert("Device ID CRP already exists.");
        device2.chalHash = chalHash;
        device2.respHash = respHash;

        DeviceInfo storage device1 = devicesinfo[deviceId];
        if (device1.deviceId == address(0)){
            device1.deviceId = deviceId;
            device1.owner = owner;
            device1.deviceOwnershipTrace.push(owner);
        }
    }

    // 0xC91E862338272667dc4dad2C306D924f59A53480,0000
    function authenticateDevice(address deviceId,uint256 chalHash) public view returns (uint256 ) {

         if (getAuthority(msg.sender) == PermissionLevel.None)
            revert("Sender doesn't have permission to Authenticate the Device.");

         DeviceCRP storage device = devicescrp[deviceId][chalHash];
         if (device.chalHash != chalHash)
         revert("Challenge Response Pair for this Device does not exists. Device cannot be authenticated");

         return device.respHash;

    }

    function transferOwnership(address deviceId, address newOwner) public {
        PermissionLevel x = getAuthority(msg.sender);
        if (x == PermissionLevel.None || x == PermissionLevel.Peer) {
            revert("You don't have permission to transfer ownership.");
        }
        DeviceInfo storage device = devicesinfo[deviceId];
        if (device.deviceId == address(0)) {
            revert("Device ID not found.");
        }
        device.owner = newOwner;
        device.deviceOwnershipTrace.push(newOwner);
    }

    function checkOwnership(address deviceId) public view returns (address) {
             return devicesinfo[deviceId].owner;
        }

    function storeIPFS(address deviceId,string memory ipfschalCID, string memory ipfsrespCID) public {
       IPFS storage x = ipfsfiles[deviceId];
       x.ipfschalCID = ipfschalCID;
       x.ipfsrespCID = ipfsrespCID;
    }
    function getipfschalCID(address deviceId) public view returns (string memory){
       return ipfsfiles[deviceId].ipfschalCID;
    }
    function getipfsrespCID(address deviceId) public view returns (string memory){
       return ipfsfiles[deviceId].ipfsrespCID;
    }


    receive() external payable {
        // handle incoming ether
    }

    fallback() external {
        // handle incoming function calls
    }
}