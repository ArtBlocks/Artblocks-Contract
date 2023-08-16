import { graphql } from "../generated/gql";

export const getProjectMinterConfigurationQueryDocument =
  graphql(/* GraphQL */ `
    query GetProjectMinterConfiguration($projectId: String!) {
      projects_metadata_by_pk(id: $projectId) {
        project_id
        user_is_artist

        contract {
          type {
            project_configuration_schema
          }

          user_is_allowlisted
          minter_filter {
            address
            globally_allowed_minters {
              address
              minter_type
              type {
                label
              }
            }
          }
        }
        minter_configuration {
          currency_address
          currency_symbol
          ...ProjectMinterConfigurationDetails
        }
      }
    }

    fragment ProjectMinterConfigurationDetails on project_minter_configurations {
      id
      project_id
      base_price
      currency_address
      currency_symbol
      extra_minter_details
      minter {
        address
        minter_type
        type {
          unversioned_type
          version_number
        }
      }
    }
  `);

export const getProjectMinterConfigurationUpdatesQueryDocument =
  graphql(/* GraphQL */ `
    query GetProjectMinterConfigurationUpdates($projectId: String!) {
      projects_metadata_by_pk(id: $projectId) {
        minter_configuration {
          properties_updated_at
        }
      }
    }
  `);

export const getAllowlistUploadUrlQueryDocument = graphql(/* GraphQL */ `
  query GetAllowlistUploadUrl($projectId: String!) {
    getAllowlistUploadUrl(projectId: $projectId) {
      url
      key
    }
  }
`);

export const updateOffChainExtraMinterDetailsMutationDocument =
  graphql(/* GraphQL */ `
    mutation UpdateOffChainExtraMinterDetails(
      $projectMinterConfigId: String!
      $extraMinterDetails: jsonb!
    ) {
      update_project_minter_configurations_by_pk(
        pk_columns: { id: $projectMinterConfigId }
        _append: { offchain_extra_minter_details: $extraMinterDetails }
      ) {
        offchain_extra_minter_details
      }
    }
  `);
