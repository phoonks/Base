package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"

	"log"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/gin-gonic/gin"
	cf "github.com/kahsengphoon/Base/config"
	"github.com/urfave/cli/v2"
)

const (
	mainnetRPC = "https://mainnet.base.org"
	testnetRPC = "https://base-sepolia.infura.io/v3/2015a1e9dbec42eaab3ba418a43a4b79"
	// testnetRPC     = "https://sepolia.base.org"
	mainnetChainID  = 8453
	testnetChainID  = 84532
	contractAddress = "0x198ed8881be08e0AAdd7021425cAa980863b3761"
	myAddress       = "0x1686C628EdDd1cb769EF50362B27C4dfF2A3D399"
	fromAddress     = "0x8D1dD583c808FA344Cd374Df5fB34e5434C0bf25"
	myContractABI   = `[
		{
			"inputs": [
				{
					"internalType": "uint256",
					"name": "initialSupply",
					"type": "uint256"
				}
			],
			"stateMutability": "nonpayable",
			"type": "constructor"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "spender",
					"type": "address"
				},
				{
					"internalType": "uint256",
					"name": "allowance",
					"type": "uint256"
				},
				{
					"internalType": "uint256",
					"name": "needed",
					"type": "uint256"
				}
			],
			"name": "ERC20InsufficientAllowance",
			"type": "error"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "sender",
					"type": "address"
				},
				{
					"internalType": "uint256",
					"name": "balance",
					"type": "uint256"
				},
				{
					"internalType": "uint256",
					"name": "needed",
					"type": "uint256"
				}
			],
			"name": "ERC20InsufficientBalance",
			"type": "error"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "approver",
					"type": "address"
				}
			],
			"name": "ERC20InvalidApprover",
			"type": "error"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "receiver",
					"type": "address"
				}
			],
			"name": "ERC20InvalidReceiver",
			"type": "error"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "sender",
					"type": "address"
				}
			],
			"name": "ERC20InvalidSender",
			"type": "error"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "spender",
					"type": "address"
				}
			],
			"name": "ERC20InvalidSpender",
			"type": "error"
		},
		{
			"anonymous": false,
			"inputs": [
				{
					"indexed": true,
					"internalType": "address",
					"name": "owner",
					"type": "address"
				},
				{
					"indexed": true,
					"internalType": "address",
					"name": "spender",
					"type": "address"
				},
				{
					"indexed": false,
					"internalType": "uint256",
					"name": "value",
					"type": "uint256"
				}
			],
			"name": "Approval",
			"type": "event"
		},
		{
			"anonymous": false,
			"inputs": [
				{
					"indexed": true,
					"internalType": "address",
					"name": "from",
					"type": "address"
				},
				{
					"indexed": true,
					"internalType": "address",
					"name": "to",
					"type": "address"
				},
				{
					"indexed": false,
					"internalType": "uint256",
					"name": "value",
					"type": "uint256"
				}
			],
			"name": "Transfer",
			"type": "event"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "owner",
					"type": "address"
				},
				{
					"internalType": "address",
					"name": "spender",
					"type": "address"
				}
			],
			"name": "allowance",
			"outputs": [
				{
					"internalType": "uint256",
					"name": "",
					"type": "uint256"
				}
			],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "spender",
					"type": "address"
				},
				{
					"internalType": "uint256",
					"name": "value",
					"type": "uint256"
				}
			],
			"name": "approve",
			"outputs": [
				{
					"internalType": "bool",
					"name": "",
					"type": "bool"
				}
			],
			"stateMutability": "nonpayable",
			"type": "function"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "account",
					"type": "address"
				}
			],
			"name": "balanceOf",
			"outputs": [
				{
					"internalType": "uint256",
					"name": "",
					"type": "uint256"
				}
			],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [],
			"name": "decimals",
			"outputs": [
				{
					"internalType": "uint8",
					"name": "",
					"type": "uint8"
				}
			],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [],
			"name": "name",
			"outputs": [
				{
					"internalType": "string",
					"name": "",
					"type": "string"
				}
			],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [],
			"name": "symbol",
			"outputs": [
				{
					"internalType": "string",
					"name": "",
					"type": "string"
				}
			],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [],
			"name": "totalSupply",
			"outputs": [
				{
					"internalType": "uint256",
					"name": "",
					"type": "uint256"
				}
			],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "to",
					"type": "address"
				},
				{
					"internalType": "uint256",
					"name": "value",
					"type": "uint256"
				}
			],
			"name": "transfer",
			"outputs": [
				{
					"internalType": "bool",
					"name": "",
					"type": "bool"
				}
			],
			"stateMutability": "nonpayable",
			"type": "function"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "from",
					"type": "address"
				},
				{
					"internalType": "address",
					"name": "to",
					"type": "address"
				},
				{
					"internalType": "uint256",
					"name": "value",
					"type": "uint256"
				}
			],
			"name": "transferFrom",
			"outputs": [
				{
					"internalType": "bool",
					"name": "",
					"type": "bool"
				}
			],
			"stateMutability": "nonpayable",
			"type": "function"
		}
	]`
)

type BaseTransaction struct {
	BlockHash             string   `json:"blockHash"`
	BlockNumber           string   `json:"blockNumber"`
	From                  string   `json:"from"`
	To                    string   `json:"to"`
	Gas                   string   `json:"gas"`
	GasPrice              string   `json:"gasPrice"`
	Hash                  string   `json:"hash"`
	Input                 string   `json:"input"`
	Nonce                 string   `json:"nonce"`
	TransactionIndex      string   `json:"transactionIndex"`
	Value                 string   `json:"value"`
	Type                  string   `json:"type"`
	ChainID               string   `json:"chainId,omitempty"`              // Optional
	AccessList            []string `json:"accessList,omitempty"`           // Optional
	MaxFeePerGas          string   `json:"maxFeePerGas,omitempty"`         // Optional
	MaxPriorityFeePerGas  string   `json:"maxPriorityFeePerGas,omitempty"` // Optional
	R                     string   `json:"r"`
	S                     string   `json:"s"`
	V                     string   `json:"v"`
	SourceHash            string   `json:"sourceHash,omitempty"`            // Optional
	DepositReceiptVersion string   `json:"depositReceiptVersion,omitempty"` // Optional
	Mint                  string   `json:"mint,omitempty"`                  // Optional
	YParity               string   `json:"yParity,omitempty"`               // Optional
}

type BaseBlock struct {
	BaseFeePerGas         string            `json:"baseFeePerGas"`
	BlobGasUsed           string            `json:"blobGasUsed"`
	Difficulty            string            `json:"difficulty"`
	ExcessBlobGas         string            `json:"excessBlobGas"`
	ExtraData             string            `json:"extraData"`
	GasLimit              string            `json:"gasLimit"`
	GasUsed               string            `json:"gasUsed"`
	Hash                  string            `json:"hash"`
	LogsBloom             string            `json:"logsBloom"`
	Miner                 string            `json:"miner"`
	MixHash               string            `json:"mixHash"`
	Nonce                 string            `json:"nonce"`
	Number                string            `json:"number"`
	ParentHash            string            `json:"parentHash"`
	ParentBeaconBlockRoot string            `json:"parentBeaconBlockRoot,omitempty"` // Optional
	ReceiptsRoot          string            `json:"receiptsRoot"`
	Sha3Uncles            string            `json:"sha3Uncles"`
	Size                  string            `json:"size"`
	StateRoot             string            `json:"stateRoot"`
	Timestamp             string            `json:"timestamp"`
	Transactions          []BaseTransaction `json:"transactions"`
	TransactionsRoot      string            `json:"transactionsRoot"`
	Uncles                []string          `json:"uncles"`
	Withdrawals           []string          `json:"withdrawals,omitempty"`     // Optional
	WithdrawalsRoot       string            `json:"withdrawalsRoot,omitempty"` // Optional
}

// For high-value transactions, wait for 12 confirmations.
// For everyday transactions, 3 confirmations are typically sufficient.

func (h *HttpServer) StartListenerServer(c *cli.Context) error {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	if h.isStarted {
		return errors.New("Server already started")
	}

	r := gin.New()
	r.Use(gin.Recovery())
	h.isStarted = true
	h.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", h.port),
		Handler: r,
	}

	ConnectBase()
	if err := r.Run(fmt.Sprintf(":%v", cf.Enviroment().AppServerPort)); err != nil {
		return err
	}

	return nil
}

func ConnectBase() {
	// Create grpc connection
	// Connect to Base (Mainnet or Testnet)
	rpcClient, err := rpc.Dial(testnetRPC) // Replace with the appropriate RPC URL
	if err != nil {
		log.Fatalf("Failed to connect to Base: %v", err)
	}
	defer rpcClient.Close()

	contractABI, err := abi.JSON(strings.NewReader(myContractABI))

	// Custom RPC call for eth_getBlockByNumber
	var result map[string]interface{}
	blockNumber := big.NewInt(20063335)
	err = rpcClient.CallContext(context.Background(), &result, "eth_getBlockByNumber", toBlockNumArg(blockNumber), true)
	if err != nil {
		log.Fatalf("Failed to fetch block: %v", err)
	}

	// // Print the result in JSON format
	// jsonTestData, _ := json.MarshalIndent(result, "", "  ")
	// fmt.Println(string(jsonTestData))

	// Print block details
	jsonData, err := json.Marshal(result)
	if err != nil {
		log.Fatalf("Failed to marshal result: %v", err)
	}

	var block BaseBlock
	err = json.Unmarshal(jsonData, &block)
	if err != nil {
		log.Fatalf("Failed to unmarshal JSON into struct: %v", err)
	}

	// Print the block data
	// Print parsed block data
	blockNumberInt, err := hexToInt64(block.Number)
	if err != nil {
		fmt.Printf("[ERR] blockNumberInt: %+v\n", err)
	}
	fmt.Printf("Block Number: %v\n", blockNumberInt)
	fmt.Printf("Block Hash: %v\n", block.Hash)
	fmt.Printf("Miner: %v\n", block.Miner)

	baseFeePerGasInt, err := hexToInt64(block.BaseFeePerGas)
	if err != nil {
		fmt.Printf("Error converting hex to decimal: %v\n", err)
		return
	}
	fmt.Printf("Base Fee Per Gas: %v\n", baseFeePerGasInt)

	gasLimitInt, err := hexToInt64(block.GasLimit)
	if err != nil {
		fmt.Printf("Error converting hex to decimal: %v\n", err)
		return
	}
	fmt.Printf("Gas Limit: %v\n", gasLimitInt)

	gasUsedInt, err := hexToInt64(block.GasUsed)
	if err != nil {
		fmt.Printf("Error converting hex to decimal: %v\n", err)
		return
	}
	fmt.Printf("Gas Used: %v\n", gasUsedInt)
	fmt.Printf("Transactions Count: %d\n\n", len(block.Transactions))

	// Print transactions
	for i, tx := range block.Transactions {
		if !(strings.EqualFold(tx.To, myAddress) || strings.EqualFold(tx.From, fromAddress)) {
			continue
		}

		fmt.Printf("Transaction %d:\n", i+1)
		fmt.Printf("Hash: %v\n", tx.Hash)
		fmt.Printf("From: %v\n", tx.From)
		fmt.Printf("To: %v\n", tx.To)

		gasInt, err := hexToInt64(tx.Gas)
		if err != nil {
			fmt.Printf("Error converting hex to decimal: %v\n", err)
			return
		}
		fmt.Printf("Gas Limit: %d\n", gasInt)

		gasPriceInt, err := hexToInt64(tx.GasPrice)
		if err != nil {
			fmt.Printf("Error converting hex to decimal: %v\n", err)
			return
		}
		fmt.Printf("Gas Price: %v\n", gasPriceInt)

		maxFeePerGasInt, err := hexToInt64(tx.MaxFeePerGas)
		if err != nil {
			fmt.Printf("Error converting hex to decimal: %v\n", err)
			return
		}
		fmt.Printf("Max Fee Per Gas: %v\n", maxFeePerGasInt)

		maxPriorityFeePerGasInt, err := hexToInt64(tx.MaxPriorityFeePerGas)
		if err != nil {
			fmt.Printf("Error converting hex to decimal: %v\n", err)
			return
		}
		fmt.Printf("Max Priority Fee Per Gas: %v\n", maxPriorityFeePerGasInt)

		// Print the transaction fee
		l2Fee := new(big.Int).Mul(new(big.Int).SetUint64(gasInt), new(big.Int).SetUint64(gasPriceInt))
		fmt.Printf("L2 Fees Paid: %s wei\n", l2Fee)

		ethFactor := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil) // 10^18
		transactionFeeInEth := new(big.Float).Quo(
			new(big.Float).SetInt(l2Fee),
			new(big.Float).SetInt(ethFactor),
		)
		fmt.Printf("Transaction Fees: %v wei\n", transactionFeeInEth)

		nonceInt, err := hexToInt64(tx.Nonce)
		if err != nil {
			fmt.Printf("Error converting hex to decimal: %v\n", err)
			return
		}
		fmt.Printf("Nonce: %v\n", nonceInt)

		typeInt, err := hexToInt64(tx.Type)
		if err != nil {
			fmt.Printf("Error converting hex to decimal: %v\n", err)
			return
		}
		fmt.Printf("Type: %v\n", typeInt)

		transactionIndexInt, err := hexToInt64(tx.TransactionIndex)
		if err != nil {
			fmt.Printf("Error converting hex to decimal: %v\n", err)
			return
		}
		fmt.Printf("Transaction Index: %v\n", transactionIndexInt)

		valueInt, err := hexToInt64(tx.Value)
		if err != nil {
			fmt.Printf("Error converting hex to decimal: %v\n", err)
			return
		}
		fmt.Printf("Value: %v\n", valueInt)

		if len(tx.To) > 0 && strings.EqualFold(tx.To, contractAddress) {
			// Decode the input data
			inputData, err := hex.DecodeString(tx.Input[2:]) // Strip "0x"
			if err != nil {
				log.Fatalf("Failed to decode input data: %v", err)
			}

			if len(inputData) > 0 {
				method, err := contractABI.MethodById(inputData[:4])
				if err != nil {
					fmt.Println("Error finding method by ID:", err)
				}
				fmt.Printf("Method: %s\n", method.Name)

				args, err := method.Inputs.Unpack(inputData[4:])
				if err != nil {
					fmt.Println("Error unpacking method inputs:", err)
				}
				fmt.Printf("Arguments: %v\n", args)
			}
			if len(inputData) >= 4 && hex.EncodeToString(inputData[:4]) == "a9059cbb" { // `transfer` method signature
				// Extract the recipient address and amount
				recipient := common.BytesToAddress(inputData[4:36])
				amount := new(big.Int).SetBytes(inputData[36:])

				// Check if the recipient is your address
				if strings.EqualFold(recipient.String(), myAddress) {
					fmt.Printf("WCC transfer to %s detected in transaction %s\n", myAddress, tx.Hash)
					fmt.Printf("Amount: %s\n", amount.String())
				}
			}
		}
		fmt.Printf("----------\n")
	}
}

func hexToInt64(hex string) (uint64, error) {
	if len(hex) == 0 {
		return 0, nil
	}
	// Convert from hex to decimal
	return strconv.ParseUint(hex[2:], 16, 64)
}
func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	if number.Sign() >= 0 {
		return hexutil.EncodeBig(number)
	}
	// It's negative.
	if number.IsInt64() {
		return rpc.BlockNumber(number.Int64()).String()
	}
	// It's negative and large, which is invalid.
	return fmt.Sprintf("<invalid %d>", number)
}
