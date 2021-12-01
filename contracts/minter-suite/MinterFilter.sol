import "../libs/SafeMath.sol";

import "../interfaces/IMinterFilter.sol";
import "../interfaces/IGenArt721CoreContract.sol";

pragma solidity ^0.5.0;

contract MinterFilter is IMinterFilter {
    using SafeMath for uint256;

    event DefaultMinterRegistered(address indexed _minterAddress);
    event ProjectMinterRegistered(
        uint256 indexed _projectId,
        address indexed _minterAddress
    );

    IGenArt721CoreContract public artblocksContract;

    address public defaultMinter;

    mapping(uint256 => address) public minterForProject;

    modifier onlyCoreWhitelisted() {
        require(
            artblocksContract.isWhitelisted(msg.sender),
            "Only Core whitelisted"
        );
        _;
    }

    modifier onlyCoreWhitelistedOrArtist(uint256 _projectId) {
        require(
            (artblocksContract.isWhitelisted(msg.sender) ||
                msg.sender ==
                artblocksContract.projectIdToArtistAddress(_projectId)),
            "Only Core whitelisted or Artist"
        );
        _;
    }

    constructor(address _genArt721Address) public {
        artblocksContract = IGenArt721CoreContract(_genArt721Address);
    }

    function setDefaultMinter(address _minterAddress)
        external
        onlyCoreWhitelisted
    {
        defaultMinter = _minterAddress;
        emit DefaultMinterRegistered(_minterAddress);
    }

    function setMinterForProject(uint256 _projectId, address _minterAddress)
        external
        onlyCoreWhitelistedOrArtist(_projectId)
    {
        minterForProject[_projectId] = _minterAddress;
        emit ProjectMinterRegistered(_projectId, _minterAddress);
    }

    function resetMinterForProjectToDefault(uint256 _projectId)
        external
        onlyCoreWhitelistedOrArtist(_projectId)
    {
        minterForProject[_projectId] = address(0);
        emit ProjectMinterRegistered(_projectId, address(0));
    }

    function mint(
        address _to,
        uint256 _projectId,
        address sender
    ) external returns (uint256 _tokenId) {
        require(
            (msg.sender == minterForProject[_projectId]) ||
                (minterForProject[_projectId] == address(0) &&
                    msg.sender == defaultMinter),
            "Not sent from correct minter for project"
        );
        uint256 tokenId = artblocksContract.mint(_to, _projectId, sender);
        return tokenId;
    }
}
