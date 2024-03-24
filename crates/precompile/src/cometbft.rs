use crate::{Error, Precompile, PrecompileResult, PrecompileError, PrecompileWithAddress};
use cometbft_light_client::{predicates::VerificationPredicates, types::{LightBlock, TrustThreshold}};
use revm_primitives::Bytes;
use cometbft_light_client_verifier::{types::{ValidatorSet, Validator}, predicates::ProdPredicates, operations::voting_power::ProdVotingPowerCalculator};
use cometbft::vote::Power;
use cometbft::PublicKey;
use cometbft::{block::signed_header::SignedHeader, validator::Set};
use cometbft_proto::types::v1::LightBlock as TmLightBlock;
use prost::Message;

pub const COMETBFT_LIGHT_BLOCK_VALIDATION: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(103),
    Precompile::Standard(cometbft_light_block_validation_run),
);

const UINT64_TYPE_LENGTH: u64 = 8;
const CONSENSUS_STATE_LENGTH_BYTES_LENGTH: u64 = 32;
const VALIDATE_RESULT_METADATA_LENGTH: u64 = 32;

const CHAIN_ID_LENGTH: u64 = 32;
const HEIGHT_LENGTH: u64 = 8;
const VALIDATOR_SET_HASH_LENGTH: u64 = 32;
const VALIDATOR_PUBKEY_LENGTH: u64 = 32;
const VALIDATOR_VOTING_POWER_LENGTH: u64 = 8;
const RELAYER_ADDRESS_LENGTH: u64 = 20;
const RELAYER_BLS_KEY_LENGTH: u64 = 48;

const SINGLE_VALIDATOR_BYTES_LENGTH: u64 =
    VALIDATOR_PUBKEY_LENGTH + VALIDATOR_VOTING_POWER_LENGTH + RELAYER_ADDRESS_LENGTH + RELAYER_BLS_KEY_LENGTH;

const MAX_CONSENSUS_STATE_LENGTH: u64 =
    CHAIN_ID_LENGTH + HEIGHT_LENGTH + VALIDATOR_SET_HASH_LENGTH + 99 * SINGLE_VALIDATOR_BYTES_LENGTH;


fn cometbft_light_block_validation_run(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    const COMETBFT_LIGHT_BLOCK_VALIDATION_BASE: u64 = 3_000;

    if COMETBFT_LIGHT_BLOCK_VALIDATION_BASE > gas_limit {
        return Err(Error::OutOfGas);
    }

    let (mut consensus_state, tm_light_block) = match decode_light_block_validation_input(input) {
        Ok(result) => result,
        Err(e) => return Err(e),
    };

    let light_block = match convert_light_block_from_proto(&tm_light_block) {
        Ok(lb) => lb,
        Err(e) => return Err(e),
    };

    let validator_set_changed = match consensus_state.apply_light_block(&light_block) {
        Ok(validator_set_changed) => validator_set_changed,
        Err(e) => return Err(e),
    };
    
    let consensus_state_bytes = match consensus_state.encode() {
        Ok(cs) => cs,
        Err(e) => return Err(e),
    };

    Ok((COMETBFT_LIGHT_BLOCK_VALIDATION_BASE, encode_light_block_validation_result(validator_set_changed, consensus_state_bytes)))
}

type ConvertLightBlockResult = Result<LightBlock, PrecompileError>;
fn convert_light_block_from_proto(light_block_proto: &TmLightBlock) -> ConvertLightBlockResult {
    let signed_header = match SignedHeader::try_from(light_block_proto.signed_header.as_ref().unwrap().clone()) {
        Ok(sh) => sh.clone(),
        Err(_) => return Err(Error::CometBftInvalidInput),
    };
   
    let validator_set = match Set::try_from(light_block_proto.validator_set.as_ref().unwrap().clone()) {
        Ok(vs) => vs.clone(),
        Err(_) => return Err(Error::CometBftInvalidInput),
    };
    
    let next_validator_set = validator_set.clone();
    let peer_id = cometbft::node::Id::new([0u8; 20]);
    Ok(LightBlock::new(signed_header, validator_set, next_validator_set, peer_id))
}

type DecodeLightBlockResult = Result<(ConsensusState, TmLightBlock), PrecompileError>;
fn decode_light_block_validation_input(input: &Bytes) -> DecodeLightBlockResult{
    let input_length = input.len() as u64;
    if input_length < CONSENSUS_STATE_LENGTH_BYTES_LENGTH {
        return Err(Error::CometBftInvalidInput);
    }

    let cs_length = u64::from_be_bytes(input[CONSENSUS_STATE_LENGTH_BYTES_LENGTH as usize - UINT64_TYPE_LENGTH as usize..CONSENSUS_STATE_LENGTH_BYTES_LENGTH as usize].try_into().unwrap());
    let input_length_checked = CONSENSUS_STATE_LENGTH_BYTES_LENGTH.checked_add(cs_length);
    if input_length_checked.is_none() { // overflow
        return Err(Error::CometBftInvalidInput);
    }

    if input_length < input_length_checked.unwrap() {
        return Err(Error::CometBftInvalidInput);
    }

    let consensus_state = match decode_consensus_state(&input) {
        Ok(cs) => cs,
        Err(e) => return Err(e),
    };
    
    let mut light_block_pb: TmLightBlock = TmLightBlock::default();
    match light_block_pb.merge(&input[CONSENSUS_STATE_LENGTH_BYTES_LENGTH as usize +cs_length as usize..]) {
        Ok(_) => (),
        Err(_) => return Err(Error::CometBftInvalidInput),
    };
    
    Ok((consensus_state, light_block_pb))
}

struct ConsensusState {
    chain_id: String,
    height: u64,
    next_validator_set_hash: Bytes,
    validators: ValidatorSet,
    relayer_address: Vec<Bytes>,
    relayer_bls_key: Vec<Bytes>,
}

impl ConsensusState {
    fn new(chain_id: String, height: u64, next_validator_set_hash: Bytes, validators: ValidatorSet, relayer_address: Vec<Bytes>, relayer_bls_key: Vec<Bytes>) -> Self {
        Self {
            chain_id,
            height,
            next_validator_set_hash,
            validators,
            relayer_address,
            relayer_bls_key,
        }
    }

    fn apply_light_block(&mut self, light_block: &LightBlock) -> Result<bool, Error> {
        // TODO: enhance checking
        if light_block.signed_header.header().chain_id.as_str() != self.chain_id {
            return Ok(false);
        }

        let vp = ProdPredicates;
        let voting_power_calculator = ProdVotingPowerCalculator::default();
        let trust_threshold_two_third = TrustThreshold::TWO_THIRDS;
        let trust_threshold_one_third = TrustThreshold::ONE_THIRD;
        if self.height + 1 == light_block.height().value() {
            if self.next_validator_set_hash.ne(light_block.validators.hash().as_bytes()) {
                return Ok(false);
            }
            // Verify Commit Light Trusted
            let result = vp.has_sufficient_validators_overlap(&light_block.signed_header, &light_block.validators,&trust_threshold_two_third, &voting_power_calculator);
            if !result.is_ok() {
                return Ok(false);
            }
        } else {
            // Verify Commit Light Trusting
            let result = vp.has_sufficient_validators_overlap(&light_block.signed_header, &self.validators, &trust_threshold_one_third, &voting_power_calculator);
            if !result.is_ok() {
                return Ok(false);
            }
            
            // Verify Commit Light
            let result = vp.has_sufficient_validators_overlap(&light_block.signed_header, &light_block.validators,&trust_threshold_two_third, &voting_power_calculator);
            if !result.is_ok() {
                return Ok(false);
            }
        }
        
        let validator_set_changed = self.validators.hash().as_bytes().ne(light_block.validators.hash().as_bytes());
        self.height = light_block.height().value();
        self.next_validator_set_hash = Bytes::from(light_block.signed_header.header().next_validators_hash.as_bytes().to_vec());
        self.validators = light_block.validators.clone();

        Ok(validator_set_changed)
    }

    fn encode(&self) -> Result<Bytes, Error> {
        let validator_set_length = self.validators.validators().len();
        let serialize_length = (CHAIN_ID_LENGTH + HEIGHT_LENGTH + VALIDATOR_SET_HASH_LENGTH + validator_set_length as u64 * SINGLE_VALIDATOR_BYTES_LENGTH) as usize;
        if serialize_length > MAX_CONSENSUS_STATE_LENGTH as usize {
            return Err(Error::CometBftEncodeConsensusStateFailed);
        }
        if self.chain_id.len() > CHAIN_ID_LENGTH as usize {
            return Err(Error::CometBftEncodeConsensusStateFailed);
        }

        let mut output = Vec::new();
        output.resize(serialize_length, 0);
        let mut pos: usize = 0;
        output[pos..pos + CHAIN_ID_LENGTH as usize].copy_from_slice(self.chain_id.as_bytes());
        pos += CHAIN_ID_LENGTH as usize;

        output[pos..pos + HEIGHT_LENGTH as usize].copy_from_slice(&self.height.to_be_bytes());
        pos += HEIGHT_LENGTH as usize;

        output[pos..pos + VALIDATOR_SET_HASH_LENGTH as usize].copy_from_slice(self.next_validator_set_hash.as_ref());
        pos += VALIDATOR_SET_HASH_LENGTH as usize;

        for i in 0..validator_set_length {
            let validator = &self.validators.validators()[i];
            let voting_power = validator.power();

            output[pos..pos + VALIDATOR_PUBKEY_LENGTH as usize].copy_from_slice(&validator.pub_key.to_bytes());
            pos += VALIDATOR_PUBKEY_LENGTH as usize;

            output[pos..pos + VALIDATOR_VOTING_POWER_LENGTH as usize].copy_from_slice(&voting_power.to_be_bytes());
            pos += VALIDATOR_VOTING_POWER_LENGTH as usize;

            output[pos..pos + RELAYER_ADDRESS_LENGTH as usize].copy_from_slice(self.relayer_address[i].as_ref());
            pos += RELAYER_ADDRESS_LENGTH as usize;

            output[pos..pos + RELAYER_BLS_KEY_LENGTH as usize].copy_from_slice(self.relayer_bls_key[i].as_ref());
            pos += RELAYER_BLS_KEY_LENGTH as usize;
        }

        Ok(Bytes::from(output))
    }
}

type DecodeConsensusStateResult = Result<ConsensusState, PrecompileError>;
/// input:
/// | chainID   | height   | nextValidatorSetHash | [{validator pubkey, voting power, relayer address, relayer bls pubkey}] |
/// | 32 bytes  | 8 bytes  | 32 bytes             | [{32 bytes, 8 bytes, 20 bytes, 48 bytes}]     
fn decode_consensus_state(input: &Bytes) -> DecodeConsensusStateResult{
    let minimum_length = CHAIN_ID_LENGTH+HEIGHT_LENGTH+VALIDATOR_SET_HASH_LENGTH;
	let input_length = input.len() as u64;
	if input_length <= minimum_length || (input_length-minimum_length)%SINGLE_VALIDATOR_BYTES_LENGTH != 0 {
        return Err(Error::CometBftInvalidInput);
    }

    let mut pos = 0 as u64;
    let chain_id = &input[..CHAIN_ID_LENGTH as usize];
    let chain_id = String::from_utf8_lossy(chain_id).trim().to_owned();
    pos += CHAIN_ID_LENGTH;

    let height = u64::from_be_bytes(input[pos as usize..(pos+HEIGHT_LENGTH) as usize].try_into().unwrap());
    pos += HEIGHT_LENGTH;

    let next_validator_set_hash = Bytes::from(input[pos as usize..(pos+VALIDATOR_SET_HASH_LENGTH) as usize].to_vec());
    pos += VALIDATOR_SET_HASH_LENGTH;
    
    let validator_set_length = (input_length - minimum_length) / SINGLE_VALIDATOR_BYTES_LENGTH;
    let validator_set_bytes = input[pos as usize..].to_vec();
    let mut validator_set = Vec::with_capacity(validator_set_length as usize);
    let mut relayer_address_set = Vec::with_capacity(validator_set_length as usize);
    let mut relayer_bls_key_set = Vec::with_capacity(validator_set_length as usize);
    for i in 0..validator_set_length {
        let validator = &validator_set_bytes[i as usize * SINGLE_VALIDATOR_BYTES_LENGTH as usize..(i+1) as usize * SINGLE_VALIDATOR_BYTES_LENGTH as usize];

        let voting_power = u64::from_be_bytes(validator[VALIDATOR_PUBKEY_LENGTH as usize..(VALIDATOR_PUBKEY_LENGTH+VALIDATOR_VOTING_POWER_LENGTH) as usize].try_into().unwrap());
        let relayer_address = Bytes::from(validator[(VALIDATOR_PUBKEY_LENGTH+VALIDATOR_VOTING_POWER_LENGTH) as usize..(VALIDATOR_PUBKEY_LENGTH+VALIDATOR_VOTING_POWER_LENGTH+RELAYER_ADDRESS_LENGTH) as usize].to_vec());
        let relayer_bls_key = Bytes::from(validator[(VALIDATOR_PUBKEY_LENGTH+VALIDATOR_VOTING_POWER_LENGTH+RELAYER_ADDRESS_LENGTH) as usize..].to_vec());
        let pk = match PublicKey::from_raw_ed25519(&validator[..VALIDATOR_PUBKEY_LENGTH as usize]) {
            Some(pk) => pk,
            None => return Err(Error::CometBftInvalidInput),
        };
        let vp = Power::from(voting_power as u32);
        let validator_info = Validator::new(pk, vp);
        validator_set.push(validator_info);
        relayer_address_set.push(relayer_address);
        relayer_bls_key_set.push(relayer_bls_key);
    }

    Ok(ConsensusState::new(chain_id, height, next_validator_set_hash,  ValidatorSet::without_proposer(validator_set), relayer_address_set, relayer_bls_key_set))
}

/// output:
/// | validatorSetChanged | empty      | consensusStateBytesLength |  new consensusState |
/// | 1 byte              | 23 bytes   | 8 bytes                   |                     |
fn encode_light_block_validation_result(validator_set_changed: bool, consensus_state_bytes: Bytes) -> Bytes {
    let mut output = Vec::new();
    output.resize(VALIDATE_RESULT_METADATA_LENGTH as usize, 0);
    output[0] = if validator_set_changed { 1 } else { 0 };
    output[1..].copy_from_slice(consensus_state_bytes.as_ref());
    Bytes::from(output)
}