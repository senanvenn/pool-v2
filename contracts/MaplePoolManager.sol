// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.7;

import {VennFirewallConsumer} from "@ironblocks/firewall-consumer/contracts/consumers/VennFirewallConsumer.sol";
import { ERC20Helper }           from "../modules/erc20-helper/src/ERC20Helper.sol";
import { IMapleProxyFactory }    from "../modules/maple-proxy-factory/contracts/interfaces/IMapleProxyFactory.sol";
import { IMapleProxied }         from "../modules/maple-proxy-factory/contracts/interfaces/IMapleProxied.sol";
import { MapleProxiedInternals } from "../modules/maple-proxy-factory/contracts/MapleProxiedInternals.sol";

import { MaplePoolManagerStorage } from "./proxy/MaplePoolManagerStorage.sol";

import {
    IERC20Like,
    IGlobalsLike,
    ILoanLike,
    ILoanManagerLike,
    IPoolDelegateCoverLike,
    IPoolLike,
    IPoolPermissionManagerLike,
    IWithdrawalManagerLike
} from "./interfaces/Interfaces.sol";

import { IMaplePoolManager } from "./interfaces/IMaplePoolManager.sol";

/*

   ███╗   ███╗ █████╗ ██████╗ ██╗     ███████╗
   ████╗ ████║██╔══██╗██╔══██╗██║     ██╔════╝
   ██╔████╔██║███████║██████╔╝██║     █████╗
   ██║╚██╔╝██║██╔══██║██╔═══╝ ██║     ██╔══╝
   ██║ ╚═╝ ██║██║  ██║██║     ███████╗███████╗
   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝


   ██████╗  ██████╗  ██████╗ ██╗         ███╗   ███╗ █████╗ ███╗   ██╗ █████╗  ██████╗ ███████╗██████╗
   ██╔══██╗██╔═══██╗██╔═══██╗██║         ████╗ ████║██╔══██╗████╗  ██║██╔══██╗██╔════╝ ██╔════╝██╔══██╗
   ██████╔╝██║   ██║██║   ██║██║         ██╔████╔██║███████║██╔██╗ ██║███████║██║  ███╗█████╗  ██████╔╝
   ██╔═══╝ ██║   ██║██║   ██║██║         ██║╚██╔╝██║██╔══██║██║╚██╗██║██╔══██║██║   ██║██╔══╝  ██╔══██╗
   ██║     ╚██████╔╝╚██████╔╝███████╗    ██║ ╚═╝ ██║██║  ██║██║ ╚████║██║  ██║╚██████╔╝███████╗██║  ██║
   ╚═╝      ╚═════╝  ╚═════╝ ╚══════╝    ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝

*/

contract MaplePoolManager is VennFirewallConsumer, IMaplePoolManager, MapleProxiedInternals, MaplePoolManagerStorage {

    uint256 public constant HUNDRED_PERCENT = 100_0000;  // Four decimal precision.

    /**************************************************************************************************************************************/
    /*** Modifiers                                                                                                                      ***/
    /**************************************************************************************************************************************/

    modifier nonReentrant() {
        if (_locked != 1) revert PoolManagerLocked();

        _locked = 2;

        _;

        _locked = 1;
    }

    modifier onlyIfNotConfigured() {
        _revertIfConfigured();
        _;
    }

    modifier onlyPoolDelegateOrNotConfigured() {
        _revertIfConfiguredAndNotPoolDelegate();
        _;
    }

    modifier onlyPool() {
        _revertIfNotPool();
        _;
    }

    modifier onlyPoolDelegate() {
        _revertIfNotPoolDelegate();
        _;
    }

    modifier onlyPoolDelegateOrProtocolAdmins() {
        _revertIfNeitherPoolDelegateNorProtocolAdmins();
        _;
    }

    modifier whenNotPaused() {
        _revertIfPaused();
        _;
    }

    /**************************************************************************************************************************************/
    /*** Migration Functions                                                                                                            ***/
    /**************************************************************************************************************************************/

    // NOTE: Can't add whenProtocolNotPaused modifier here, as globals won't be set until
    //       initializer.initialize() is called, and this function is what triggers that initialization.
    function migrate(address migrator_, bytes calldata arguments_) external override whenNotPaused  {
        if (msg.sender != _factory()) revert NotFactory();
        if (!_migrate(migrator_, arguments_)) revert MigrationFailed();
        if (poolDelegateCover == address(0)) revert DelegateNotSet();
    }

    function setImplementation(address implementation_) external override whenNotPaused  {
        if (msg.sender != _factory()) revert NotFactory();
        _setImplementation(implementation_);
    }

    function upgrade(uint256 version_, bytes calldata arguments_) external override whenNotPaused  {
        IGlobalsLike globals_ = IGlobalsLike(globals());

        if (msg.sender == poolDelegate) {
            if (!globals_.isValidScheduledCall(msg.sender, address(this), "PM:UPGRADE", msg.data)) revert InvalidScheduledCall();

            globals_.unscheduleCall(msg.sender, "PM:UPGRADE", msg.data);
        } else {
            if (msg.sender != globals_.securityAdmin()) revert NotAuthorized();
        }

        emit Upgraded(version_, arguments_);

        IMapleProxyFactory(_factory()).upgradeInstance(version_, arguments_);
    }

    /**************************************************************************************************************************************/
    /*** Initial Configuration Function                                                                                                 ***/
    /**************************************************************************************************************************************/

    // NOTE: This function is always called atomically during the deployment process so a DoS attack is not possible.
    function completeConfiguration() external override whenNotPaused onlyIfNotConfigured  {
        configured = true;

        emit PoolConfigurationComplete();
    }

    /**************************************************************************************************************************************/
    /*** Ownership Transfer Functions                                                                                                   ***/
    /**************************************************************************************************************************************/

    function acceptPoolDelegate() external override whenNotPaused firewallProtected {
        if (msg.sender != pendingPoolDelegate) revert NotPendingPoolDelegate();

        IGlobalsLike(globals()).transferOwnedPoolManager(poolDelegate, msg.sender);

        emit PendingDelegateAccepted(poolDelegate, pendingPoolDelegate);

        poolDelegate        = pendingPoolDelegate;
        pendingPoolDelegate = address(0);
    }

    function setPendingPoolDelegate(address pendingPoolDelegate_) external override payable whenNotPaused onlyPoolDelegateOrProtocolAdmins  {
        pendingPoolDelegate = pendingPoolDelegate_;

        emit PendingDelegateSet(poolDelegate, pendingPoolDelegate_);
    }

    /**************************************************************************************************************************************/
    /*** Globals Admin Functions                                                                                                        ***/
    /**************************************************************************************************************************************/

    function setActive(bool active_) external override whenNotPaused  {
        if (msg.sender != globals()) revert NotGlobals();
        emit SetAsActive(active = active_);
    }

    /**************************************************************************************************************************************/
    /*** Pool Delegate Admin Functions                                                                                                  ***/
    /**************************************************************************************************************************************/

    function addLoanManager(address loanManagerFactory_)
        external override payable whenNotPaused onlyPoolDelegateOrNotConfigured returns (address loanManager_)
    {
        if (!IGlobalsLike(globals()).isInstanceOf("LOAN_MANAGER_FACTORY", loanManagerFactory_)) revert InvalidLoanManagerFactory();

        // NOTE: If removing loan managers is allowed in the future, there will be a need to rethink salts here due to collisions.
        loanManager_ = IMapleProxyFactory(loanManagerFactory_).createInstance(
            abi.encode(address(this)),
            keccak256(abi.encode(address(this), loanManagerList.length))
        );

        isLoanManager[loanManager_] = true;

        loanManagerList.push(loanManager_);

        emit LoanManagerAdded(loanManager_);
    }

    function setDelegateManagementFeeRate(uint256 delegateManagementFeeRate_)
        external override payable whenNotPaused onlyPoolDelegateOrNotConfigured 
    {
        if (delegateManagementFeeRate_ > HUNDRED_PERCENT) revert DelegateManagementFeeRateOutOfBounds();

        emit DelegateManagementFeeRateSet(delegateManagementFeeRate = delegateManagementFeeRate_);
    }

    function setIsLoanManager(address loanManager_, bool isLoanManager_) external override payable whenNotPaused onlyPoolDelegate firewallProtected {
        emit IsLoanManagerSet(loanManager_, isLoanManager[loanManager_] = isLoanManager_);

        // Check LoanManager is in the list.
        // NOTE: The factory and instance check are not required as the mapping is being updated for a LoanManager that is in the list.
        for (uint256 i_; i_ < loanManagerList.length; ++i_) {
            if (loanManagerList[i_] == loanManager_) return;
        }

        revert InvalidLoanManager();
    }

    function setLiquidityCap(uint256 liquidityCap_) external override payable whenNotPaused onlyPoolDelegateOrNotConfigured  {
        emit LiquidityCapSet(liquidityCap = liquidityCap_);
    }

    function setWithdrawalManager(address withdrawalManager_) external override payable whenNotPaused onlyIfNotConfigured firewallProtected {
        address factory_ = IMapleProxied(withdrawalManager_).factory();

        if (!IGlobalsLike(globals()).isInstanceOf("WITHDRAWAL_MANAGER_FACTORY", factory_)) revert InvalidWithdrawalManagerFactory();
        if (!IMapleProxyFactory(factory_).isInstance(withdrawalManager_)) revert InvalidWithdrawalManagerInstance();

        emit WithdrawalManagerSet(withdrawalManager = withdrawalManager_);
    }

    function setPoolPermissionManager(address poolPermissionManager_) external override payable whenNotPaused onlyPoolDelegateOrNotConfigured  {
        if (!IGlobalsLike(globals()).isInstanceOf("POOL_PERMISSION_MANAGER", poolPermissionManager_)) revert InvalidPoolPermissionManagerInstance();

        emit PoolPermissionManagerSet(poolPermissionManager = poolPermissionManager_);
    }

    /**************************************************************************************************************************************/
    /*** Funding Functions                                                                                                              ***/
    /**************************************************************************************************************************************/

    function requestFunds(address destination_, uint256 principal_) external override whenNotPaused nonReentrant firewallProtected {
        address asset_   = asset;
        address pool_    = pool;
        address factory_ = IMapleProxied(msg.sender).factory();

        IGlobalsLike globals_ = IGlobalsLike(globals());

        if (principal_ == 0) revert InvalidPrincipal();
        if (!globals_.isInstanceOf("LOAN_MANAGER_FACTORY", factory_)) revert InvalidFactory();
        if (!IMapleProxyFactory(factory_).isInstance(msg.sender)) revert InvalidInstance();
        if (!isLoanManager[msg.sender]) revert NotLoanManager();
        if (IERC20Like(pool_).totalSupply() == 0) revert ZeroSupply();
        if (!_hasSufficientCover(address(globals_), asset_)) revert InsufficientCover();

        // Fetching locked liquidity needs to be done prior to transferring the tokens.
        uint256 lockedLiquidity_ = IWithdrawalManagerLike(withdrawalManager).lockedLiquidity();

        if (destination_ == address(0)) revert InvalidDestination();
        if (!ERC20Helper.transferFrom(asset_, pool_, destination_, principal_)) revert TransferFailed();

        if (IERC20Like(asset_).balanceOf(pool_) < lockedLiquidity_) revert InsufficientLockedLiquidity();
    }

    /**************************************************************************************************************************************/
    /*** Loan Default Functions                                                                                                         ***/
    /**************************************************************************************************************************************/

    function finishCollateralLiquidation(address loan_) external override payable whenNotPaused nonReentrant onlyPoolDelegateOrProtocolAdmins firewallProtected {
        ( uint256 losses_, uint256 platformFees_ ) = ILoanManagerLike(_getLoanManager(loan_)).finishCollateralLiquidation(loan_);

        _handleCover(losses_, platformFees_);

        emit CollateralLiquidationFinished(loan_, losses_);
    }

    function triggerDefault(address loan_, address liquidatorFactory_)
        external override payable whenNotPaused nonReentrant onlyPoolDelegateOrProtocolAdmins firewallProtected
    {
        if (!IGlobalsLike(globals()).isInstanceOf("LIQUIDATOR_FACTORY", liquidatorFactory_)) revert InvalidLiquidatorFactory();

        (
            bool    liquidationComplete_,
            uint256 losses_,
            uint256 platformFees_
        ) = ILoanManagerLike(_getLoanManager(loan_)).triggerDefault(loan_, liquidatorFactory_);

        if (!liquidationComplete_) {
            emit CollateralLiquidationTriggered(loan_);
            return;
        }

        _handleCover(losses_, platformFees_);

        emit CollateralLiquidationFinished(loan_, losses_);
    }

    /**************************************************************************************************************************************/
    /*** Pool Exit Functions                                                                                                            ***/
    /**************************************************************************************************************************************/

    function processRedeem(uint256 shares_, address owner_, address sender_)
        external override whenNotPaused nonReentrant onlyPool  returns (uint256 redeemableShares_, uint256 resultingAssets_)
    {
        if (owner_ != sender_ || IPoolLike(pool).allowance(owner_, sender_) == 0) revert NoAllowance();

        ( redeemableShares_, resultingAssets_ ) = IWithdrawalManagerLike(withdrawalManager).processExit(shares_, owner_);
        emit RedeemProcessed(owner_, redeemableShares_, resultingAssets_);
    }

    function processWithdraw(uint256 assets_, address owner_, address sender_)
        external override whenNotPaused nonReentrant firewallProtected returns (uint256 redeemableShares_, uint256 resultingAssets_)
    {
        assets_; owner_; sender_; redeemableShares_; resultingAssets_;  // Silence compiler warnings
        if (true) revert NotEnabled();
    }

    function removeShares(uint256 shares_, address owner_)
        external override whenNotPaused nonReentrant onlyPool  returns (uint256 sharesReturned_)
    {
        emit SharesRemoved(
            owner_,
            sharesReturned_ = IWithdrawalManagerLike(withdrawalManager).removeShares(shares_, owner_)
        );
    }

    function requestRedeem(uint256 shares_, address owner_, address sender_) external override whenNotPaused nonReentrant onlyPool  {
        address pool_ = pool;

        if (!ERC20Helper.approve(pool_, withdrawalManager, shares_)) revert ApproveFailed();

        if (sender_ != owner_ && shares_ == 0) {
            if (IPoolLike(pool_).allowance(owner_, sender_) == 0) revert NoAllowance();
        }

        IWithdrawalManagerLike(withdrawalManager).addShares(shares_, owner_);

        emit RedeemRequested(owner_, shares_);
    }

    function requestWithdraw(uint256 shares_, uint256 assets_, address owner_, address sender_)
        external override whenNotPaused nonReentrant firewallProtected
    {
        shares_; assets_; owner_; sender_;  // Silence compiler warnings
        if (true) revert NotEnabled();
    }

    /**************************************************************************************************************************************/
    /*** Pool Delegate Cover Functions                                                                                                  ***/
    /**************************************************************************************************************************************/

    function depositCover(uint256 amount_) external override whenNotPaused firewallProtected {
        if (!ERC20Helper.transferFrom(asset, msg.sender, poolDelegateCover, amount_)) revert TransferFailed();
        emit CoverDeposited(amount_);
    }

    function withdrawCover(uint256 amount_, address recipient_) external override whenNotPaused onlyPoolDelegate  {
        recipient_ = recipient_ == address(0) ? msg.sender : recipient_;

        IPoolDelegateCoverLike(poolDelegateCover).moveFunds(amount_, recipient_);

        if (IERC20Like(asset).balanceOf(poolDelegateCover) < IGlobalsLike(globals()).minCoverAmount(address(this))) revert InsufficientCover();

        emit CoverWithdrawn(amount_);
    }

    /**************************************************************************************************************************************/
    /*** View Functions                                                                                                                 ***/
    /**************************************************************************************************************************************/

    function canCall(bytes32 functionId_, address caller_, bytes calldata data_)
        external view override returns (bool canCall_, string memory errorMessage_)
    {
        if (IGlobalsLike(globals()).isFunctionPaused(msg.sig)) return (false, "PM:CC:PAUSED");

        uint256[3] memory params_ = _decodeParameters(data_);

        uint256 assets_ = params_[0];
        address lender_ = _address(params_[1]);

        // For mint functions there's a need to convert shares into assets.
        if (functionId_ == "P:mint" || functionId_ == "P:mintWithPermit") assets_ = IPoolLike(pool).previewMint(params_[0]);

        // Redeem and withdraw require getting the third word from the calldata.
        if ( functionId_ == "P:redeem" || functionId_ == "P:withdraw") lender_ = _address(params_[2]);

        // Transfers need to check both the sender and the recipient.
        if (functionId_ == "P:transfer" || functionId_ == "P:transferFrom") {
            address[] memory lenders_ = new address[](2);

            ( lenders_[0], lenders_[1] ) = functionId_ == "P:transfer" ?
                (caller_,              _address(params_[0])) :
                (_address(params_[0]), _address(params_[1]));

            // Check both lenders in a single call.
            if (!IPoolPermissionManagerLike(poolPermissionManager).hasPermission(address(this), lenders_, functionId_)) {
                return (false, "PM:CC:NOT_ALLOWED");
            }

        } else {
            if (!IPoolPermissionManagerLike(poolPermissionManager).hasPermission(address(this), lender_, functionId_)) {
                return (false, "PM:CC:NOT_ALLOWED");
            }
        }

        if (
            functionId_ == "P:redeem"          ||
            functionId_ == "P:withdraw"        ||
            functionId_ == "P:removeShares"    ||
            functionId_ == "P:requestRedeem"   ||
            functionId_ == "P:requestWithdraw" ||
            functionId_ == "P:transfer"        ||
            functionId_ == "P:transferFrom"
        ) return (true, "");

        if (
            functionId_ == "P:deposit"           ||
            functionId_ == "P:depositWithPermit" ||
            functionId_ == "P:mint"              ||
            functionId_ == "P:mintWithPermit"
        ) return _canDeposit(assets_);

        return (false, "PM:CC:INVALID_FUNCTION_ID");
    }

    function factory() external view override returns (address factory_) {
        factory_ = _factory();
    }

    function globals() public view override returns (address globals_) {
        globals_ = IMapleProxyFactory(_factory()).mapleGlobals();
    }

    function governor() public view override returns (address governor_) {
        governor_ = IGlobalsLike(globals()).governor();
    }

    function hasSufficientCover() public view override returns (bool hasSufficientCover_) {
        hasSufficientCover_ = _hasSufficientCover(globals(), asset);
    }

    function implementation() external view override returns (address implementation_) {
        implementation_ = _implementation();
    }

    function loanManagerListLength() external view override returns (uint256 loanManagerListLength_) {
        loanManagerListLength_ = loanManagerList.length;
    }

    function totalAssets() public view override returns (uint256 totalAssets_) {
        totalAssets_ = IERC20Like(asset).balanceOf(pool);

        uint256 length_ = loanManagerList.length;

        for (uint256 i_; i_ < length_;) {
            totalAssets_ += ILoanManagerLike(loanManagerList[i_]).assetsUnderManagement();
            unchecked { ++i_; }
        }
    }

    /**************************************************************************************************************************************/
    /*** LP Token View Functions                                                                                                        ***/
    /**************************************************************************************************************************************/

    function convertToExitShares(uint256 assets_) public view override returns (uint256 shares_) {
        shares_ = IPoolLike(pool).convertToExitShares(assets_);
    }

    function getEscrowParams(address, uint256 shares_) external view override returns (uint256 escrowShares_, address destination_) {
        // NOTE: `owner_` param not named to avoid compiler warning.
        ( escrowShares_, destination_) = (shares_, address(this));
    }

    function maxDeposit(address receiver_) external view virtual override returns (uint256 maxAssets_) {
        maxAssets_ = _getMaxAssets(receiver_, totalAssets(), "P:deposit");
    }

    function maxMint(address receiver_) external view virtual override returns (uint256 maxShares_) {
        uint256 totalAssets_ = totalAssets();
        uint256 maxAssets_   = _getMaxAssets(receiver_, totalAssets_, "P:mint");

        maxShares_ = IPoolLike(pool).previewDeposit(maxAssets_);
    }

    function maxRedeem(address owner_) external view virtual override returns (uint256 maxShares_) {
        uint256 lockedShares_ = IWithdrawalManagerLike(withdrawalManager).lockedShares(owner_);
        maxShares_            = IWithdrawalManagerLike(withdrawalManager).isInExitWindow(owner_) ? lockedShares_ : 0;
    }

    function maxWithdraw(address owner_) external view virtual override returns (uint256 maxAssets_) {
        owner_;          // Silence compiler warning
        maxAssets_ = 0;  // NOTE: always returns 0 as withdraw is not implemented
    }

    function previewRedeem(address owner_, uint256 shares_) external view virtual override returns (uint256 assets_) {
        ( , assets_ ) = IWithdrawalManagerLike(withdrawalManager).previewRedeem(owner_, shares_);
    }

    function previewWithdraw(address owner_, uint256 assets_) external view virtual override returns (uint256 shares_) {
        ( , shares_ ) = IWithdrawalManagerLike(withdrawalManager).previewWithdraw(owner_, assets_);
    }

    function unrealizedLosses() public view override returns (uint256 unrealizedLosses_) {
        uint256 length_ = loanManagerList.length;

        for (uint256 i_; i_ < length_;) {
            unrealizedLosses_ += ILoanManagerLike(loanManagerList[i_]).unrealizedLosses();
            unchecked { ++i_; }
        }

        // NOTE: Use minimum to prevent underflows in the case that `unrealizedLosses` includes late interest and `totalAssets` does not.
        unrealizedLosses_ = _min(unrealizedLosses_, totalAssets());
    }

    /**************************************************************************************************************************************/
    /*** Internal Helper Functions                                                                                                      ***/
    /**************************************************************************************************************************************/

    function _getLoanManager(address loan_) internal view returns (address loanManager_) {
        loanManager_ = ILoanLike(loan_).lender();

        if (!isLoanManager[loanManager_]) revert InvalidLoanManager();
    }

    function _handleCover(uint256 losses_, uint256 platformFees_) internal {
        address globals_ = globals();

        uint256 availableCover_ =
            IERC20Like(asset).balanceOf(poolDelegateCover) * IGlobalsLike(globals_).maxCoverLiquidationPercent(address(this)) /
            HUNDRED_PERCENT;

        uint256 toTreasury_ = _min(availableCover_,               platformFees_);
        uint256 toPool_     = _min(availableCover_ - toTreasury_, losses_);

        if (toTreasury_ != 0) {
            IPoolDelegateCoverLike(poolDelegateCover).moveFunds(toTreasury_, IGlobalsLike(globals_).mapleTreasury());
        }

        if (toPool_ != 0) {
            IPoolDelegateCoverLike(poolDelegateCover).moveFunds(toPool_, pool);
        }

        emit CoverLiquidated(toTreasury_, toPool_);
    }

    /**************************************************************************************************************************************/
    /*** Internal Functions                                                                                                             ***/
    /**************************************************************************************************************************************/

    function _address(uint256 word_) internal pure returns (address address_) {
        address_ = address(uint160(word_));
    }

    function _canDeposit(uint256 assets_) internal view returns (bool canDeposit_, string memory errorMessage_) {
        if (!active)                                return (false, "P:NOT_ACTIVE");
        if (assets_ + totalAssets() > liquidityCap) return (false, "P:DEPOSIT_GT_LIQ_CAP");

        return (true, "");
    }

    function _decodeParameters(bytes calldata data_) internal pure returns (uint256[3] memory words) {
        if (data_.length > 64)  {
            ( words[0], words[1], words[2] ) = abi.decode(data_, (uint256, uint256, uint256));
        } else {
            ( words[0], words[1] ) = abi.decode(data_, (uint256, uint256));
        }
    }

    function _getMaxAssets(address receiver_, uint256 totalAssets_, bytes32 functionId_) internal view returns (uint256 maxAssets_) {
        bool    depositAllowed_ = IPoolPermissionManagerLike(poolPermissionManager).hasPermission(address(this),  receiver_, functionId_);
        uint256 liquidityCap_   = liquidityCap;
        maxAssets_              = liquidityCap_ > totalAssets_ && depositAllowed_ ? liquidityCap_ - totalAssets_ : 0;
    }

    function _hasSufficientCover(address globals_, address asset_) internal view returns (bool hasSufficientCover_) {
        hasSufficientCover_ = IERC20Like(asset_).balanceOf(poolDelegateCover) >= IGlobalsLike(globals_).minCoverAmount(address(this));
    }

    function _min(uint256 a_, uint256 b_) internal pure returns (uint256 minimum_) {
        minimum_ = a_ < b_ ? a_ : b_;
    }

    function _revertIfConfigured() internal view {
        if (configured) revert AlreadyConfigured();
    }

    function _revertIfConfiguredAndNotPoolDelegate() internal view {
        if (configured || msg.sender != poolDelegate) revert NotAuthorized();
    }

    function _revertIfNotPool() internal view {
        if (msg.sender != pool) revert NotPool();
    }

    function _revertIfNotPoolDelegate() internal view {
        if (msg.sender != poolDelegate) revert NotPoolDelegate();
    }

    function _revertIfNeitherPoolDelegateNorProtocolAdmins() internal view {
        if (
            msg.sender != poolDelegate ||
            msg.sender != governor() ||
            msg.sender != IGlobalsLike(globals()).operationalAdmin()
        ) revert NotPoolDelegateOrGovernorOrOperationalAdmin();
    }

    function _revertIfPaused() internal view {
        if (IGlobalsLike(globals()).isFunctionPaused(msg.sig)) revert Paused();
    }

}

// Add these custom error definitions at the end of the file
error PoolManagerLocked();
error NotFactory();
error MigrationFailed();
error DelegateNotSet();
error InvalidScheduledCall();
error NotAuthorized();
error InvalidPrincipal();
error InvalidFactory();
error InvalidInstance();
error NotLoanManager();
error ZeroSupply();
error InsufficientCover();
error InvalidDestination();
error TransferFailed();
error InsufficientLockedLiquidity();
error DelegateManagementFeeRateOutOfBounds();
error InvalidLoanManager();
error InvalidWithdrawalManagerFactory();
error InvalidWithdrawalManagerInstance();
error InvalidPoolPermissionManagerInstance();
error InvalidLiquidatorFactory();
error Paused();
error NotPendingPoolDelegate();
error NotGlobals();
error InvalidLoanManagerFactory();
error AlreadyConfigured();
error NotPool();
error NotPoolDelegate();
error NotPoolDelegateOrGovernorOrOperationalAdmin();
error NoAllowance();
error NotEnabled();
error ApproveFailed();