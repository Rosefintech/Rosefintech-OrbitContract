// SPDX-License-Identifier: SimPL-2.0
pragma experimental ABIEncoderV2;
pragma solidity ^0.6.12;


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
            set._indexes[lastvalue] = toDeleteIndex + 1;

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

interface IERC20 {
    function balanceOf(address _addr) external view returns (uint);

    function transfer(address _to, uint _value) external returns (bool);
    function symbol() external view returns (string memory);
}

interface Exchange{
    function getAmountsOut(uint _tokenNum,address _symbolAddress, address _returnSymbolAddress) external view returns (uint);
}

interface FundExchange {
    function fundToken2TokenCallback(
        address _fetch_address,
        address _return_address,
        uint _tokenNum,
        uint _queryId
    ) external returns (uint);

    function fundToken2ETHCallback(
        address _fetch_address,
        uint _tokenNum,
        uint _queryId
    ) external returns (uint);

    function fundETH2TokenCallback(
        address _return_address,
        uint _tokenNum,
        uint _queryId
    ) external payable returns (uint);
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

contract FundManageData is AccessControl {
    using SafeMath for uint;
    EnumerableSet.AddressSet ERC20Address;

    address public _exchangeAddress;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN");
    bytes32 public constant DISPATCH_ROLE = keccak256("FUND_DISPATCH");
    bytes32 public constant EXCHANGE_ROLE = keccak256("FUND_EXCHANGE");

    uint public _deviation = 10;

    address public WETH;
    address public USDC;
    address public chargeAddr;
    address public brokerageAddr;

    event PositionLog(bytes32 _id, address _addr, uint _ethNum, uint _usdcNum, uint _timestamp);

    event OutOfPositionLog(
        address _account,
        address _tokenAddr,
        uint _billNum,
        uint _tokenNum,
        uint tokenBrokerageNum,
        uint _tokenChargeNum,
        uint _timestamp
    );

    event ExchangeLog(address _fetchAddress, address _returnAddress, uint _fetchNum, uint _returnNum, uint _timestamp);

    function setWETH(address _WETHAddress) public roleCheck(ADMIN_ROLE) {
        WETH = _WETHAddress;
    }

    function setUSDC(address _USDCAddress) public roleCheck(ADMIN_ROLE) {
        address _usdc = USDC;
        if (_usdc != address(0)) {
            ERC20Address.remove(_usdc);
        }
        ERC20Address.add(_USDCAddress);
        USDC = _USDCAddress;
    }

    function setDeviation(uint _dev) external roleCheck(ADMIN_ROLE) {
        _deviation = _dev;
    }

    function setBrokerageAddress(address _brokerageAddr) external roleCheck(ADMIN_ROLE) {
        brokerageAddr = _brokerageAddr;
    }

    function setExchangeAddress(address _exchangeContract) external roleCheck(ADMIN_ROLE) {
        _exchangeAddress = _exchangeContract;
    }

    function setChargeAddress(address _chargeAddress) external roleCheck(ADMIN_ROLE) {
        chargeAddr = _chargeAddress;
    }

    function addFundERC20(address _addr) public roleCheck(ADMIN_ROLE) returns (bool) {
        return ERC20Address.add(_addr);
    }

    function removeFundERC20(address _addr) external roleCheck(ADMIN_ROLE) returns (bool) {
        return ERC20Address.remove(_addr);
    }

    constructor() public {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(ADMIN_ROLE, msg.sender);
    }

    modifier roleCheck(bytes32 role) {
        require(hasRole(role, msg.sender), "FUNDMANAGE:DON'T_HAVE_PERMISSION");
        _;
    }
}

contract FundManageView is FundManageData {
    function getAssert() public view returns (uint _eth, string[] memory _erc20Symbol, uint[] memory _balance) {
        _eth = address(this).balance;
        address[] memory _erc20Contract = getFundERC20Address();
        uint _len = _erc20Contract.length;
        _erc20Symbol = new string[](_len);
        _balance = new uint[](_len);
        for (uint i = 0; i < _len; i++) {
            IERC20 _erc20 = IERC20(_erc20Contract[i]);
            _erc20Symbol[i] = _erc20.symbol();
            _balance[i] = _erc20.balanceOf(address(this));
        }
    }

    function getFundERC20Address() public view returns (address[] memory) {
        uint _len = ERC20Address.length();
        address[] memory res = new address[](_len);
        for (uint i = 0; i < _len; i++) {
            res[i] = ERC20Address.at(i);
        }
        return res;
    }
}

contract FundManage is FundManageView {
    constructor(
        address _wbtcAddress,
        address _usdcAddress,
        address _WETHAddress
    ) public {
        addFundERC20(_wbtcAddress);
        setUSDC(_usdcAddress);
        setWETH(_WETHAddress);
    }

    function fetchETH2Token(
        address _return_address,
        uint _tokenNum,
        uint _queryId
    ) external roleCheck(EXCHANGE_ROLE) returns (uint) {
        require(ERC20Address.contains(_return_address), "RETURN_ADDRESS_NOT_FUND");

        require(address(this).balance >= _tokenNum, "INSUFFICIENT_BALANCE");
        IERC20 returnContract = IERC20(_return_address);
        uint _return_balance = returnContract.balanceOf(address(this));

        uint _exchange = Exchange(_exchangeAddress).getAmountsOut(_tokenNum, WETH, _return_address);
        uint _return_num = FundExchange(msg.sender).fundETH2TokenCallback{value:_tokenNum}(_return_address, _tokenNum, _queryId);
        require(_return_num.add(_return_num.mul(_deviation).div(1000)) >= _exchange, "Excessive exchange rate misalignment!");
        if (_return_balance.add(_return_num) <= returnContract.balanceOf(address(this))) {
            emit ExchangeLog(address(0), _return_address, _tokenNum, _return_num, block.timestamp);
            return _return_num;
        } else {
            revert();
        }
    }

    function fetchToken2ETH(
        address _fetch_address,
        uint _tokenNum,
        uint _queryId
    ) external roleCheck(EXCHANGE_ROLE) returns (uint) {
        require(ERC20Address.contains(_fetch_address), "FETCH_ADDRESS_NOT_FUND");

        IERC20 fetchContract = IERC20(_fetch_address);
        require(fetchContract.balanceOf(address(this)) >= _tokenNum, "INSUFFICIENT_BALANCE");

        if (_transferToken(msg.sender, _tokenNum, _fetch_address)) {
            uint _return_balance = address(this).balance;
            uint _exchange = Exchange(_exchangeAddress).getAmountsOut(_tokenNum, _fetch_address, WETH);
            uint _return_num = FundExchange(msg.sender).fundToken2ETHCallback(_fetch_address, _tokenNum, _queryId);
            require(_return_num.add(_return_num.mul(_deviation).div(1000)) >= _exchange, "Excessive exchange rate misalignment!");

            if (_return_balance.add(_return_num) <= address(this).balance) {
                emit ExchangeLog(_fetch_address, address(0), _tokenNum, _return_num, block.timestamp);
                return _return_num;
            }
        }
        revert();
    }

    function _transferToken(
        address _to,
        uint _value,
        address _erc20Addr
    ) internal returns (bool) {
        require(IERC20(_erc20Addr).balanceOf(address(this)) >= _value, "Transfer out more than the maximum amount!");
        return IERC20(_erc20Addr).transfer(_to, _value);
    }

    function fetchToken2Token(
        address _fetch_address,
        address _return_address,
        uint _tokenNum,
        uint _queryId
    ) external roleCheck(EXCHANGE_ROLE) returns (uint) {
        require(ERC20Address.contains(_fetch_address), "FETCH_ADDRESS_NOT_FUND");
        require(ERC20Address.contains(_return_address), "RETURN_ADDRESS_NOT_FUND");

        IERC20 fetchContract = IERC20(_fetch_address);
        require(fetchContract.balanceOf(address(this)) >= _tokenNum, "INSUFFICIENT_BALANCE");

        if (_transferToken(msg.sender, _tokenNum, _fetch_address)) {
            IERC20 returnContract = IERC20(_return_address);
            uint _return_balance = returnContract.balanceOf(address(this));

            uint _exchange = Exchange(_exchangeAddress).getAmountsOut(_tokenNum, _fetch_address, _return_address);
            uint _return_num = FundExchange(msg.sender).fundToken2TokenCallback(_fetch_address, _return_address, _tokenNum, _queryId);
            require(_return_num.add(_return_num.mul(_deviation).div(1000)) >= _exchange, "Excessive exchange rate misalignment!");

            if (_return_balance.add(_return_num) <= returnContract.balanceOf(address(this))) {
                emit ExchangeLog(_fetch_address, _return_address, _tokenNum, _return_num, block.timestamp);
                return _return_num;
            }
        }
        revert();
    }

    function takePosition(address _account, uint _usdcNum, bytes32 _id) external payable roleCheck(DISPATCH_ROLE) returns (bool) {
        require(msg.value > 0, "ETH_ZERO");
        uint _timestamp = block.timestamp;
        emit PositionLog(_id, _account, msg.value, _usdcNum, _timestamp);
        return true;
    }

    function outOfPosition(
        address[] memory _addr,
        address tokenAddr,
        uint[] memory tokenNum,
        uint[] memory billTokenNum,
        uint[] memory tokenBrokerageNum,
        uint[] memory tokenChargeNum
    ) external roleCheck(DISPATCH_ROLE) returns (uint _tokenRes) {
        require(ERC20Address.contains(tokenAddr), "ERC20_NOT_FUND");
        require(chargeAddr != address(0), "CHARGE_ADDRESS_ZERO");

        uint _len = tokenNum.length;
        uint _charge;
        uint _brokerage;
        for (uint i = 0; i < _len; i++) {
            _outOfPosition(
                _addr[i],
                tokenAddr,
                billTokenNum[i],
                tokenNum[i],
                tokenChargeNum[i],
                tokenBrokerageNum[i]
            );
            _tokenRes = _tokenRes.add(tokenNum[i]);
            _charge = _charge.add(tokenChargeNum[i]);
            _brokerage = _brokerage.add(tokenBrokerageNum[i]);
        }
        chargeGrant(chargeAddr, tokenAddr, _charge);
        chargeGrant(brokerageAddr, tokenAddr, _brokerage);
        _tokenRes = _tokenRes.add(_charge).add(_brokerage);
    }

    function chargeGrant(
        address _receiveAddr,
        address _tokenAddr,
        uint _tokenChargeNum
    ) internal {
        if (_tokenChargeNum > 0 && _tokenAddr != address(0)) {
            _transferToken(_receiveAddr, _tokenChargeNum, _tokenAddr);
        }
    }

    function _outOfPosition(
        address _account,
        address _tokenAddr,
        uint _billNum,
        uint _tokenNum,
        uint _tokenChargeNum,
        uint tokenBrokerageNum
    ) internal {

        if (_tokenNum > 0) {
            _transferToken(_account, _tokenNum, _tokenAddr);
        }

        emit OutOfPositionLog(
            _account,
            _tokenAddr,
            _billNum,
            _tokenNum,
            tokenBrokerageNum,
            _tokenChargeNum,
            block.timestamp
        );
    }

    receive() external payable {
        require(hasRole(EXCHANGE_ROLE, msg.sender), "FUNDMANAGE:DON'T_HAVE_PERMISSION");
    }
}
