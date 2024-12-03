// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.7;

import { IGlobalsLike, IMapleProxyFactoryLike } from "../interfaces/Interfaces.sol";
import { IMaplePoolManagerInitializer }         from "../interfaces/IMaplePoolManagerInitializer.sol";

import { MaplePool }               from "../MaplePool.sol";
import { MaplePoolDelegateCover }  from "../MaplePoolDelegateCover.sol";
import { MaplePoolManagerStorage } from "./MaplePoolManagerStorage.sol";

contract MaplePoolManagerInitializer is IMaplePoolManagerInitializer, MaplePoolManagerStorage {

    error ZeroPoolDelegate();
    error ZeroAsset();
    error NotPoolDelegate();
    error AlreadyPoolOwner();
    error AssetNotAllowed();
    error InvalidPoolParams();

    function decodeArguments(bytes calldata encodedArguments_) public pure override
        returns (
            address poolDelegate_,
            address asset_,
            uint256 initialSupply_,
            string memory name_,
            string memory symbol_
        )
    {
        (
            poolDelegate_,
            asset_,
            initialSupply_,
            name_,
            symbol_
        ) = abi.decode(encodedArguments_, (address, address, uint256, string, string));
    }

    function encodeArguments(
        address poolDelegate_,
        address asset_,
        uint256 initialSupply_,
        string memory name_,
        string memory symbol_
    )
        external pure override returns (bytes memory encodedArguments_)
    {
        encodedArguments_ = abi.encode(poolDelegate_, asset_, initialSupply_, name_, symbol_);
    }

    fallback() external {
        _locked = 1;

        (
            address poolDelegate_,
            address asset_,
            uint256 initialSupply_,
            string memory name_,
            string memory symbol_
        ) = decodeArguments(msg.data);

        _initialize(poolDelegate_, asset_, initialSupply_,  name_, symbol_);
    }

    function _initialize(
        address poolDelegate_,
        address asset_,
        uint256 initialSupply_,
        string memory name_,
        string memory symbol_
    ) internal {
        address globals_ = IMapleProxyFactoryLike(msg.sender).mapleGlobals();

        if ((poolDelegate = poolDelegate_) == address(0)) revert ZeroPoolDelegate();
        if ((asset = asset_) == address(0)) revert ZeroAsset();

        if (!IGlobalsLike(globals_).isPoolDelegate(poolDelegate_)) revert NotPoolDelegate();
        if (IGlobalsLike(globals_).ownedPoolManager(poolDelegate_) != address(0)) revert AlreadyPoolOwner();
        if (!IGlobalsLike(globals_).isPoolAsset(asset_)) revert AssetNotAllowed();

        address migrationAdmin_ = IGlobalsLike(globals_).migrationAdmin();

        if (initialSupply_ != 0 || migrationAdmin_ == address(0)) revert InvalidPoolParams();

        poolDelegate = poolDelegate_;
        asset = asset_;

        pool = address(
            new MaplePool(
                address(this),
                asset_,
                migrationAdmin_,
                IGlobalsLike(globals_).bootstrapMint(asset_),
                initialSupply_,
                name_,
                symbol_
            )
        );

        poolDelegateCover = address(new MaplePoolDelegateCover(address(this), asset));

        emit Initialized(poolDelegate_, asset_, address(pool));
    }

}
