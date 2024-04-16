import { AnonCredsCredentialsForProofRequest } from '@aries-framework/anoncreds'
import { AnonCredsCredentialMetadataKey } from '@aries-framework/anoncreds/build/utils/metadata'
import { CredentialExchangeRecord, ProofExchangeRecord } from '@aries-framework/core'
import { BifoldAgent } from '@hyperledger/aries-bifold-core'

const msInDay = 1000 * 60 * 60 * 24

export const attestationCredDefIds = [
  'NXp6XcGeCR2MviWuY51Dva:3:CL:33557:bcwallet',
  'RycQpZ9b4NaXuT5ZGjXkUE:3:CL:120:bcwallet',
  'XqaRXJt4sXE6TRpfGpVbGw:3:CL:655:bcwallet',
]

// proof requests can vary wildly but we'll know attestation requests
// must contain the cred def id as a restriction
interface IndyRequest {
  indy: {
    requested_attributes?: {
      attestationInfo?: {
        names: string[]
        restrictions: { cred_def_id: string }[]
      }
    }
  }
}

// same as above
interface AnonCredsRequest {
  anoncreds: {
    requested_attributes?: {
      attestationInfo?: {
        names: string[]
        restrictions: { cred_def_id: string }[]
      }
    }
  }
}

export interface AttestationProofRequestFormat {
  request: IndyRequest & AnonCredsRequest
}

export interface AttestationCredentialFormat extends AnonCredsCredentialsForProofRequest {
  attributes: {
    attestationInfo: []
  }
}

/**
 * Determine the format of the proof request
 *
 * Setting `filterByNonRevocationRequirements` to `false` returns all credentials
 * even if they are revokable and revoked.
 *
 * @param agent
 * @param proofId
 * @param filterByNonRevocationRequirements
 * @returns The Anoncreds or Indy proof format object
 */
const formatForProofWithId = async (agent: BifoldAgent, proofId: string, filterByNonRevocationRequirements = false) => {
  const format = await agent.proofs.getFormatData(proofId)
  const proofIsAnoncredsFormat = format.request?.anoncreds !== undefined
  const proofIsIndycredsFormat = format.request?.indy !== undefined
  const proofFormats = {
    // FIXME: AFJ will try to use the format, even if the value is undefined (but the key is present)
    // We should ignore the key, if the value is undefined. For now this is a workaround.
    ...(proofIsIndycredsFormat
      ? {
          indy: {
            filterByNonRevocationRequirements,
          },
        }
      : {}),

    ...(proofIsAnoncredsFormat
      ? {
          anoncreds: {
            filterByNonRevocationRequirements,
          },
        }
      : {}),
  }

  if (!proofFormats) {
    throw new Error('Unable to lookup proof request format')
  }

  return proofFormats
}

/**
 * This function checks if the proof request is asking for an attestation
 *
 * This is a basic check to see if a proof request is asking for an attestation
 * based on the credential definition ID in the proof request.
 *
 * @param proof The proof request
 * @param agent The AFJ agent
 * @returns True if the proof request is asking for an attestation
 */
export const isProofRequestingAttestation = async (
  proof: ProofExchangeRecord,
  agent: BifoldAgent
): Promise<boolean> => {
  const format = (await agent.proofs.getFormatData(proof.id)) as AttestationProofRequestFormat
  const formatToUse = format.request?.anoncreds ? 'anoncreds' : 'indy'

  return !!format.request?.[formatToUse]?.requested_attributes?.attestationInfo?.restrictions?.some((rstr) =>
    attestationCredDefIds.includes(rstr.cred_def_id)
  )
}

/**
 * This function does two things, unfortunately. It removes all outdated or revoked
 * attestation credentials and returns the remaining valid attestation credentials.
 *
 * @param agent The AFJ agent
 * @returns All available attestation credentials
 */
export const retrieveAndTrimAvailableAttestationCredentials = async (
  agent: BifoldAgent
): Promise<CredentialExchangeRecord[]> => {
  const credentials = await agent.credentials.getAll()

  return credentials.filter((record) => {
    const credDefId = record.metadata.get(AnonCredsCredentialMetadataKey)?.credentialDefinitionId

    if (credDefId && attestationCredDefIds.includes(credDefId)) {
      const dateStr = record.credentialAttributes?.find((attr) => attr.name === 'issue_date_dateint')?.value
      if (!dateStr) {
        agent.credentials.deleteById(record.id)
        return false
      }

      const year = Number(dateStr.slice(0, 4))
      const month = Number(dateStr.slice(4, 6))
      const day = Number(dateStr.slice(6, 8))
      const issueDate = new Date(year, month - 1, day)
      const now = new Date()
      const daysSince = Math.ceil((now.getTime() - issueDate.getTime()) / msInDay)
      // if revoked or more than 14 days old, delete the credential
      if (daysSince > 14 || record.revocationNotification) {
        agent.credentials.deleteById(record.id)
        return false
      }

      // if we made it this far, the attestation credential is valid
      return true
    }

    return false
  })
}

/**
 * This function checks if we need to get an attestation credential
 *
 * In-depth check to see if we need to get an attestation credential done by
 * checking if the proof request is asking for an attestation and if we have
 * the necessary credentials to fulfill the request.
 *
 * @param agent The AFJ agent
 * @param proof The proof request
 * @param filterByNonRevocationRequirements Whether to filter by non-revocation requirements, default is true
 * @returns True if we need to get an attestation credential
 * @throws {Error} Will throw an error if a problem looking up data occurs
 */
export const credentialsMatchForAttestationProof = async (
  agent: BifoldAgent,
  proof: ProofExchangeRecord,
  filterByNonRevocationRequirements = true
): Promise<boolean> => {
  const proofFormats = await formatForProofWithId(agent, proof.id, filterByNonRevocationRequirements)
  const credentials = await agent.proofs.getCredentialsForRequest({
    proofRecordId: proof.id,
    proofFormats,
  })

  if (!credentials) return false

  // TODO:(jl) Should we be checking the length of the attributes matches some
  // expected length in the proof request?
  const format = (credentials.proofFormats.anoncreds ?? credentials.proofFormats.indy) as AttestationCredentialFormat
  if (!format) return false

  return format.attributes.attestationInfo.length !== 0
}
