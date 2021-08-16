// SPDX-License-Identifier: SimPL-2.0
pragma solidity ^0.6.12;
pragma experimental ABIEncoderV2;

interface IERC20 {
    function totalSupply() external view returns (uint);

    function transferFrom(address _from, address _to, uint256 _value) external returns (bool);

    function mint(address to, uint256 amount) external;

    function burnMulti(address[] memory from, uint256[] memory amount) external;
}

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath:ADD_OVERFLOW");

        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath:SUB_UNDERFLOW");
        uint256 c = a - b;

        return c;
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath:MUL_OVERFLOW");

        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b > 0, "SafeMath:DIV_ZERO");
        uint256 c = a / b;

        return c;
    }
}

interface IFundManager {
    function takePosition(address _account, uint _usdcNum, bytes32 _id) external payable returns (bool);

    function outOfPosition(
        address[] memory _addr,
        address tokenAddr,
        uint[] memory tokenNum,
        uint[] memory billTokenNum,
        uint[] memory tokenBrokerageNum,
        uint[] memory tokenChargeNum
    ) external returns (uint _tokenRes);
}

interface IStorage {
//    function setPositionMemberValueMul(address[] memory _account, uint[] memory _value) external;

    function getTotalAssert() external view returns (uint _ethNum, uint _USDNum, uint _WBTCNum);

    function setTotalAssert(uint _ethNum, uint _USDNum, uint _WBTCNum) external;
}

interface IUniswapRouterV2 {
    function getAmountsOut(uint _tokenNum, address[] memory _symbolAddress) external view returns (uint[] memory);

    function swapExactETHForTokens(
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external payable returns (uint[] memory amounts);

    function WETH() external pure returns (address);
}

interface IRosPledge {
    function pledgeIn(address _account, uint _USDCvalue, uint _ETHValue, uint rosValue, address _superior, uint _billNum) external returns (bytes32);

    function rewardToPosition(address[] memory _account, uint[] memory _reward) external returns(bool);
}

interface IVerifier {
    function verifyTx(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[21] memory input
    ) external view returns (bool r);
}

library EnumerableSet {
    struct Set {
        bytes32[] _values;
        mapping (bytes32 => uint256) _indexes;
    }

    function _add(Set storage set, bytes32 value) private returns (bool) {
        if (!_contains(set, value)) {
            set._values.push(value);
            set._indexes[value] = set._values.length;
            return true;
        } else {
            return false;
        }
    }

    function _remove(Set storage set, bytes32 value) private returns (bool) {
        uint256 valueIndex = set._indexes[value];

        if (valueIndex != 0) {
            uint256 toDeleteIndex = valueIndex - 1;
            uint256 lastIndex = set._values.length - 1;

            bytes32 lastvalue = set._values[lastIndex];

            set._values[toDeleteIndex] = lastvalue;
            set._indexes[lastvalue] = toDeleteIndex + 1; // All indexes are 1-based

            set._values.pop();

            delete set._indexes[value];

            return true;
        } else {
            return false;
        }
    }

    function _contains(Set storage set, bytes32 value) private view returns (bool) {
        return set._indexes[value] != 0;
    }

    function _length(Set storage set) private view returns (uint256) {
        return set._values.length;
    }

    function _at(Set storage set, uint256 index) private view returns (bytes32) {
        require(set._values.length > index, "EnumerableSet: index out of bounds");
        return set._values[index];
    }

    struct Bytes32Set {
        Set _inner;
    }

    function add(Bytes32Set storage set, bytes32 value) internal returns (bool) {
        return _add(set._inner, value);
    }

    function remove(Bytes32Set storage set, bytes32 value) internal returns (bool) {
        return _remove(set._inner, value);
    }

    function contains(Bytes32Set storage set, bytes32 value) internal view returns (bool) {
        return _contains(set._inner, value);
    }

    function length(Bytes32Set storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

    function at(Bytes32Set storage set, uint256 index) internal view returns (bytes32) {
        return _at(set._inner, index);
    }

    struct AddressSet {
        Set _inner;
    }

    function add(AddressSet storage set, address value) internal returns (bool) {
        return _add(set._inner, bytes32(uint256(uint160(value))));
    }

    function remove(AddressSet storage set, address value) internal returns (bool) {
        return _remove(set._inner, bytes32(uint256(uint160(value))));
    }

    function contains(AddressSet storage set, address value) internal view returns (bool) {
        return _contains(set._inner, bytes32(uint256(uint160(value))));
    }

    function length(AddressSet storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

    function at(AddressSet storage set, uint256 index) internal view returns (address) {
        return address(uint160(uint256(_at(set._inner, index))));
    }

    struct UintSet {
        Set _inner;
    }

    function add(UintSet storage set, uint256 value) internal returns (bool) {
        return _add(set._inner, bytes32(value));
    }

    function remove(UintSet storage set, uint256 value) internal returns (bool) {
        return _remove(set._inner, bytes32(value));
    }

    function contains(UintSet storage set, uint256 value) internal view returns (bool) {
        return _contains(set._inner, bytes32(value));
    }

    function length(UintSet storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

    function at(UintSet storage set, uint256 index) internal view returns (uint256) {
        return uint256(_at(set._inner, index));
    }
}

abstract contract AccessControl {
    using EnumerableSet for EnumerableSet.AddressSet;

    struct RoleData {
        EnumerableSet.AddressSet members;
        bytes32 adminRole;
    }

    mapping (bytes32 => RoleData) private _roles;

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);

    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);

    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role].members.contains(account);
    }

    function getRoleMemberCount(bytes32 role) public view returns (uint256) {
        return _roles[role].members.length();
    }

    function getRoleMember(bytes32 role, uint256 index) public view returns (address) {
        return _roles[role].members.at(index);
    }

    function getRoleAdmin(bytes32 role) public view returns (bytes32) {
        return _roles[role].adminRole;
    }

    function grantRole(bytes32 role, address account) public virtual {
        require(hasRole(_roles[role].adminRole, msg.sender), "AccessControl: sender must be an admin to grant");

        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) public virtual {
        require(hasRole(_roles[role].adminRole, msg.sender), "AccessControl: sender must be an admin to revoke");

        _revokeRole(role, account);
    }

    function renounceRole(bytes32 role, address account) public virtual {
        require(account == msg.sender, "AccessControl: can only renounce roles for self");

        _revokeRole(role, account);
    }

    function _setupRole(bytes32 role, address account) internal virtual {
        _grantRole(role, account);
    }

    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {
        emit RoleAdminChanged(role, _roles[role].adminRole, adminRole);
        _roles[role].adminRole = adminRole;
    }

    function _grantRole(bytes32 role, address account) private {
        if (_roles[role].members.add(account)) {
            emit RoleGranted(role, account, msg.sender);
        }
    }

    function _revokeRole(bytes32 role, address account) private {
        if (_roles[role].members.remove(account)) {
            emit RoleRevoked(role, account, msg.sender);
        }
    }
}

contract ScheduleData is AccessControl {
    using SafeMath for uint;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN");
    bytes32 public constant POSITION_ROLE = keccak256("POSITION");
    bytes32 public constant WITHDRAW_ROLE = keccak256("WITHDRAW");

    address public Rose;
    address payable OPS;
    address StorageAddress;
    mapping(address => bool) fundManageAddress;
    IRosPledge IPledge;

    address public uniswapAddress = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;

    address public USDC;

    address public WETH;
    address public WBTC;

    address public BillAddress;
    address VerifierAddress;

    address signAddress;
    uint[] public PositionRate = [15, 14, 13, 12];
    uint[] public PositionRateThreshold = [0, 1 ether, 3 ether, 5 ether];

    constructor() public {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(ADMIN_ROLE, msg.sender);
    }

    modifier roleCheck(bytes32 role) {
        require(hasRole(role, msg.sender), "SCHEDULE:DON'T_HAVE_PERMISSION");
        _;
    }

    function setPositionRate(uint[] memory _rate, uint[] memory _threshold) external roleCheck(ADMIN_ROLE) {
        PositionRate = _rate;
        PositionRateThreshold = _threshold;
    }

    function setSignAddress(address _addr) external roleCheck(ADMIN_ROLE) {
        signAddress = _addr;
    }

    function setVerifierAddress(address _addr) external roleCheck(ADMIN_ROLE) {
        VerifierAddress = _addr;
    }

    function setFundManageAddress(address _fundManageContract, bool _enable) public roleCheck(ADMIN_ROLE) {
        fundManageAddress[_fundManageContract] = _enable;
    }

    function setRose(address _ros) external roleCheck(ADMIN_ROLE) {
        Rose = _ros;
    }

    function setOPSAddress(address payable _ops) external roleCheck(ADMIN_ROLE) {
        OPS = _ops;
    }

    function setRosPledgeAddr(address _rosPledge) external roleCheck(ADMIN_ROLE) {
        IPledge = IRosPledge(_rosPledge);
    }

    function setStorageAddr(address _Fund2MemAddr) external roleCheck(ADMIN_ROLE) {
        StorageAddress = _Fund2MemAddr;
    }

    function setUniswapAddress(address _addr) external roleCheck(ADMIN_ROLE) {
        uniswapAddress = _addr;
    }

    function setUSDC(address _usdc) external roleCheck(ADMIN_ROLE) {
        USDC = _usdc;
    }

    function setWETH(address _weth) external roleCheck(ADMIN_ROLE) {
        WETH = _weth;
    }
}

contract ScheduleView is ScheduleData {
    function _getRate(uint _ethNum) internal view returns (uint) {
        uint _rate = 0;
        uint[] memory _threshold = PositionRateThreshold;
        uint[] memory _rateArr = PositionRate;

        uint len = _threshold.length;
        for (uint i = 0; i < len; i++) {
            if (_ethNum > _threshold[i]) {
                _rate = _rateArr[i];
            } else {
                break;
            }
        }
        return _rate;
    }

    function _exchange(uint _ethNum, address _addr1, address _addr2) internal view returns (uint){
        IUniswapRouterV2 _uniswap = IUniswapRouterV2(uniswapAddress);
        address[] memory addr = new address[](2);
        addr[0] = _addr1;
        addr[1] = _addr2;
        uint[] memory amounts = _uniswap.getAmountsOut(_ethNum, addr);
        return amounts[1];
    }
}

contract Schedule is ScheduleView {
    constructor(
        address _Rose,
        address _storeAddress,
        address _USDC,
        address _RosePledge,
        address _bill,
        address _wbtc,
        address _VerifierAddress,
        address[] memory _fundManage
    )public{
        WETH = IUniswapRouterV2(uniswapAddress).WETH();
        Rose = _Rose;
        StorageAddress = _storeAddress;
        USDC = _USDC;
        IPledge = IRosPledge(_RosePledge);
        BillAddress = _bill;
        WBTC = _wbtc;
        VerifierAddress = _VerifierAddress;

        uint _len = _fundManage.length;
        for (uint i = 0; i < _len; i++) {
            setFundManageAddress(_fundManage[i], true);
        }
    }

    function openPosition(
        address builder,
        address periodManager,
        bool rosPay
    ) external payable roleCheck(POSITION_ROLE) returns (uint){
        require(fundManageAddress[periodManager], "FUND_MANAGE_NOT_FUND");
        (uint usdcValue, uint balanceEth, uint rosValue) = _countFeeAndVCharge(builder, rosPay);
        return _openPosition(address(0), builder, periodManager, usdcValue, balanceEth, rosValue);
    }

    function openPosition(
        address inviter,
        address builder,
        address periodManager,
        bool rosPay
    ) external payable roleCheck(POSITION_ROLE) returns (uint){
        require(fundManageAddress[periodManager], "FUND_MANAGE_NOT_FUND");
        (uint usdcValue, uint balanceEth, uint rosValue) = _countFeeAndVCharge(builder, rosPay);
        return _openPosition(inviter, builder, periodManager, usdcValue, balanceEth, rosValue);
    }

    function _countFeeAndVCharge(address builder, bool rosPay) internal returns (uint, uint, uint){
        uint finOpValue = msg.value;
        address _weth = WETH;
        address _ros = Rose;

        uint rosValue = _exchange(finOpValue, _weth, _ros);
        uint _rate = _getRate(finOpValue);

        if (rosPay) {
            uint fee = rosValue.mul(_rate * 80).div(100000);
            rosValue = rosValue.sub(fee);
            require(IERC20(_ros).transferFrom(builder, OPS, fee), "OPERATION_CHARGE_INSUFFICIENT");
        } else {
            uint fee = finOpValue.mul(_rate).div(1000);
            finOpValue = finOpValue.sub(fee);

            rosValue = rosValue.mul(1000 - _rate).div(1000);
            OPS.transfer(fee);
        }

        uint usdcValue = _exchange(finOpValue, _weth, USDC);
        return (usdcValue, finOpValue, rosValue);
    }

    function _openPosition(
        address inviter,
        address builder,
        address periodManager,
        uint usdcValue,
        uint balanceEth,
        uint rosValue
    ) internal  returns (uint _mint){
        require(builder != address(0), "Cannot be an empty address");
        require(balanceEth != 0, "The amount of warehouse building cannot be equal to 0");

        uint _totalSupply = IERC20(BillAddress).totalSupply();
        if (_totalSupply > 0){
            (uint _ethNum, uint _USDNum, uint _WBTCNum) = IStorage(StorageAddress).getTotalAssert();
            uint _eth2USDValue = _ethNum.mul(usdcValue).div(balanceEth);
            if (_WBTCNum > 0) {
                uint _wbtc2USDValue = _exchange(_WBTCNum, WBTC, USDC);
                _USDNum = _USDNum.add(_wbtc2USDValue).add(_eth2USDValue);
            } else {
                _USDNum = _USDNum.add(_eth2USDValue);
            }
            _mint = _totalSupply.mul(usdcValue).div(_USDNum);
        } else {
            _mint = balanceEth;
        }
        IERC20(BillAddress).mint(builder, _mint);

        bytes32 _id = IPledge.pledgeIn(builder, usdcValue, balanceEth, rosValue, inviter, _mint);

        IFundManager(periodManager).takePosition{value:balanceEth}(builder, usdcValue, _id);
    }

    function _withdraw(
        address periodManager,
        address[] memory _addr,
        address tokenAddr,
        uint[] memory tokenNum,
        uint[] memory rewardNum,
        uint[] memory billTokenNum,
        uint[] memory tokenChargeNum,
        uint[] memory tokenBrokerageNum
    ) internal returns (uint) {
        uint _tokenNum = IFundManager(periodManager).outOfPosition(
            _addr,
            tokenAddr,
            tokenNum,
            billTokenNum,
            tokenBrokerageNum,
            tokenChargeNum
        );

        IPledge.rewardToPosition(_addr, rewardNum);

        IERC20(BillAddress).burnMulti(_addr, billTokenNum);

        return _tokenNum;
    }

    function withdraw(
        address[2] memory _contractAddr,
        address[] memory _addr,
        uint[] memory tokenNum,
        uint[] memory rewardNum,
        uint[] memory billTokenNum,
        uint[] memory tokenChargeNum,
        uint[] memory tokenBrokerageNum,
        uint[2][2][2] memory a,
        uint[21] memory input
    ) external roleCheck(WITHDRAW_ROLE) {
        require(IVerifier(VerifierAddress).verifyTx(a[0][0], a[1], a[0][1], input), "VERIFIER_FAIL");
        require(
            tokenNum.length == rewardNum.length &&
            tokenNum.length == billTokenNum.length &&
            tokenNum.length == tokenChargeNum.length &&
            tokenNum.length == tokenBrokerageNum.length,
            "ARRAY_LENGTH_UNLIKE"
        );

        uint _tokenNum = _withdraw(
            _contractAddr[0],
            _addr,
            _contractAddr[1],
            tokenNum,
            rewardNum,
            billTokenNum,
            tokenChargeNum,
            tokenBrokerageNum
        );

        _setStorage(_contractAddr[1], _tokenNum);
    }

    function _setStorage(
        address tokenAddr,
        uint _tokenNum
    ) internal {
        IStorage _storage = IStorage(StorageAddress);
        (uint _ethNum, uint _USDNum, uint _WBTCNum) = _storage.getTotalAssert();
        if (tokenAddr == USDC) {
            _USDNum = _USDNum.sub(_tokenNum);
        } else {
            _WBTCNum = _WBTCNum.sub(_tokenNum);
        }
        _storage.setTotalAssert(_ethNum, _USDNum, _WBTCNum);
    }
}

