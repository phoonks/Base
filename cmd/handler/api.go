package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	// base58 "github.com/btcsuite/btcd/btcutil/base58"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/gin-gonic/gin"
	cf "github.com/kahsengphoon/Base/config"
	"github.com/urfave/cli/v2"
)

func (h *HttpServer) StartApiServer(c *cli.Context) error {
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

	useEIP1559 := true
	// RawTransaction(useEIP1559)
	// RawTransactionErc20(useEIP1559)

	txData := "7b2274797065223a22307832222c22636861696e4964223a2230783134613334222c226e6f6e6365223a22307833222c22746f223a22307831393865643838383162653038653061616464373032313432356361613938303836336233373631222c22676173223a22307865613630222c226761735072696365223a6e756c6c2c226d61785072696f72697479466565506572476173223a2230783830633732222c226d6178466565506572476173223a2230783132326632376633222c2276616c7565223a22307830222c22696e707574223a22307861393035396362623030303030303030303030303030303030303030303030303136383663363238656464643163623736396566353033363262323763346466663261336433393930303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030646530623662336137363430303030222c226163636573734c697374223a5b5d2c2276223a22307830222c2272223a22307830222c2273223a22307830222c2279506172697479223a22307830222c2268617368223a22307838613939353465633135633034633562666465306336666566616561336537316533376333303934353163316363636263363836376431626536646330626338227d"
	rHex := "0c7ca220469353c50cd18d36f23dca794c5cc568c95841aa008f6baf85525303"
	sHex := "45a7eec5feabab9772f2855ae7444be331c3a3555105f740a93d15f44c202f66"
	vHex := "00"
	SignSerializedTransaction(useEIP1559, txData, rHex, sHex, vHex)

	if err := r.Run(fmt.Sprintf(":%v", cf.Enviroment().AppServerPort)); err != nil {
		return err
	}

	return nil
}

func RawTransaction(useEIP1559 bool) {
	ethclient, err := ethclient.Dial(testnetRPC)
	if err != nil {
		log.Fatalf("Failed to connect to the Base network: %v", err)
	}
	defer ethclient.Close()

	// Get the current nonce
	nonce, err := ethclient.PendingNonceAt(context.Background(), common.HexToAddress(fromAddress))
	if err != nil {
		log.Fatalf("Failed to get nonce: %v", err)
	}

	// Set transaction parameters
	// Token contract address
	toAddress := common.HexToAddress(myAddress)
	value := big.NewInt(1000000000000000) // 0.001 ETH in wei
	gasLimit := uint64(21000)             // Standard gas limit for simple transfers
	baseFee := big.NewInt(12000000000)    // base fee for EIP1559
	gasTipCap := big.NewInt(2000000000)   // base fee for EIP1559
	gasPrice, err := ethclient.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatalf("Failed to get gas price: %v", err)
	}

	var tx *types.Transaction
	var signer types.Signer
	chainID := big.NewInt(testnetChainID)
	if useEIP1559 {
		// Create an EIP-1559 transaction
		signer = types.NewLondonSigner(chainID)
		tx = types.NewTx(&types.DynamicFeeTx{
			ChainID:   big.NewInt(testnetChainID),
			Nonce:     nonce,
			GasFeeCap: baseFee,   // Maximum fee you're willing to pay per unit of gas
			GasTipCap: gasTipCap, // Tip to miners
			Gas:       gasLimit,
			To:        &toAddress,
			Value:     value,
			Data:      nil,
		})
	} else {
		// Create a new transaction
		signer = types.NewEIP155Signer(chainID)
		tx = types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, nil)
	}

	// Serialize the transaction using RLP
	txByte, err := tx.MarshalJSON()
	if err != nil {
		log.Fatalf("Failed to MarshalJSON: %v", err)
	}
	fmt.Printf("txData: %+v \n", hex.EncodeToString(txByte))

	// Sign the transaction
	rawTransaction := signer.Hash(tx)
	fmt.Printf("rawTransaction: %+v \n", hex.EncodeToString(rawTransaction[:]))
}

func SignSerializedTransaction(useEIP1559 bool, txData, rHex, sHex, vHex string) string {
	// get signature from r, s, v
	signedTxByte, err := rsvToSignature(rHex, sHex, vHex)
	if err != nil {
		log.Fatalf("rsvToSignature error : %v", err)
		return ""
	}

	signedTxStr := hex.EncodeToString(signedTxByte)
	fmt.Printf("signedTxStr: %v\n", signedTxStr)

	txDataByte, err := hex.DecodeString(txData)
	if err != nil {
		log.Fatalf("txData DecodeString error : %v", err)
		return ""
	}

	ethclient, err := ethclient.Dial(testnetRPC)
	if err != nil {
		log.Fatalf("Failed to connect to the Base network: %v", err)
		return ""
	}
	defer ethclient.Close()

	// get transaction type from rawTransaction
	tx := new(types.Transaction)
	if err := json.Unmarshal((txDataByte), &tx); err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
		return ""
	}

	// combine transaction with signature
	chainID := big.NewInt(testnetChainID)
	var signer types.Signer
	if useEIP1559 {
		signer = types.NewLondonSigner(chainID)
	} else {
		signer = types.NewEIP155Signer(chainID)
	}
	tx, err = tx.WithSignature(signer, signedTxByte)
	if err != nil {
		log.Fatalf("Failed to WithSignature: %v", err)
		return ""
	}

	rawTransaction := signer.Hash(tx)
	// Recover the public key from the signature
	pubKey, err := crypto.Ecrecover(rawTransaction[:], signedTxByte)
	if err != nil {
		log.Fatalf("Failed to recover public key: %v", err)
	}

	// Derive the sender's address from the recovered public key
	publicKey, err := crypto.UnmarshalPubkey(pubKey)
	if err != nil {
		log.Fatalf("Failed to unmarshal public key: %v", err)
	}

	senderAddress := crypto.PubkeyToAddress(*publicKey)
	log.Printf("Sender Address: %s", senderAddress.Hex())

	// Query the balance of the address
	balance, err := ethclient.BalanceAt(context.Background(), senderAddress, nil)
	if err != nil {
		log.Fatalf("Failed to get balance: %v", err)
	}

	// Convert balance from Wei to Ether
	ethValue := new(big.Float).Quo(new(big.Float).SetInt(balance), big.NewFloat(1e18))
	log.Printf("Balance: %s ETH", ethValue.String())

	// Validate balance
	gasLimit := tx.Gas()
	gasPrice := tx.GasPrice()
	totalGasCost := new(big.Int).Mul(new(big.Int).SetUint64(gasLimit), gasPrice)
	totalCost := new(big.Int).Add(totalGasCost, tx.Value())
	if balance.Cmp(totalCost) < 0 {
		log.Fatalf("Insufficient funds: have %v, need %v", balance, totalCost)
		return ""
	}

	// Broadcast the transaction
	err = ethclient.SendTransaction(context.Background(), tx)
	if err != nil {
		log.Fatalf("Failed to send transaction: %v", err)
		return ""
	}

	// Retrieve and print the transaction hash
	txHash := tx.Hash().Hex()
	log.Printf("Transaction hash: %s", txHash)

	return txHash
}

func rsvToSignature(rHex, sHex, vHex string) ([]byte, error) {
	// Decode r, s, and v from hex to bytes
	r, err := hex.DecodeString(rHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode r: %v", err)
	}

	s, err := hex.DecodeString(sHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode s: %v", err)
	}

	v, err := hex.DecodeString(vHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode v: %v", err)
	}
	if len(v) != 1 {
		return nil, fmt.Errorf("v must be a single byte")
	}

	// Concatenate r, s, and v into a single signature
	signature := append(r, append(s, v[0])...)
	return signature, nil
}

func RawTransactionErc20(useEIP1559 bool) {
	// Recipient address
	recipientAddress := common.HexToAddress(myAddress)
	senderAddress := common.HexToAddress(fromAddress)
	contractAddress := common.HexToAddress(contractAddress)
	tokenABI, err := abi.JSON(strings.NewReader(myContractABI))
	if err != nil {
		log.Fatalf("Failed to abi json: %v", err)
	}

	// Amount to transfer (in Rau)
	amount := big.NewInt(1000000000000000000) // 1 WCC

	data, err := tokenABI.Pack("transfer", recipientAddress, amount)
	if err != nil {
		log.Fatalf("Failed to create transfer data: %v", err)
	}

	ethclient, err := ethclient.Dial(testnetRPC)
	if err != nil {
		log.Fatalf("Failed to connect to the Base network: %v", err)
	}
	defer ethclient.Close()

	// Get the current nonce
	nonce, err := ethclient.PendingNonceAt(context.Background(), senderAddress)
	if err != nil {
		log.Fatalf("Failed to get nonce: %v", err)
	}

	gasLimit := uint64(60000)        // Standard gas limit for simple transfers
	baseFee := big.NewInt(305080307) // base fee for EIP1559
	gasTipCap := big.NewInt(527474)  // priority fee for EIP1559
	gasPrice, err := ethclient.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatalf("Failed to get gas price: %v", err)
	}

	var tx *types.Transaction
	var signer types.Signer
	chainID := big.NewInt(testnetChainID)
	if useEIP1559 {
		// Create an EIP-1559 transaction
		signer = types.NewLondonSigner(chainID)
		tx = types.NewTx(&types.DynamicFeeTx{
			ChainID:   big.NewInt(testnetChainID),
			Nonce:     nonce,
			GasFeeCap: baseFee,   // Maximum fee you're willing to pay per unit of gas
			GasTipCap: gasTipCap, // Tip to miners
			Gas:       gasLimit,
			To:        &contractAddress,
			Value:     big.NewInt(0),
			Data:      data,
		})
	} else {
		// Create a new transaction
		signer = types.NewEIP155Signer(chainID)
		tx = types.NewTransaction(nonce, contractAddress, big.NewInt(0), gasLimit, gasPrice, data)
	}

	// Serialize the transaction using RLP
	txByte, err := tx.MarshalJSON()
	if err != nil {
		log.Fatalf("Failed to MarshalJSON: %v", err)
	}
	fmt.Printf("txData: %+v \n", hex.EncodeToString(txByte))

	// Sign the transaction
	rawTransaction := signer.Hash(tx)
	fmt.Printf("rawTransaction: %+v \n", hex.EncodeToString(rawTransaction[:]))
}
