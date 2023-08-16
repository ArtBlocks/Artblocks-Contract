import request from "graphql-request";
import get from "lodash/get";
import set from "lodash/set";
import difference from "lodash/difference";
import ArtBlocksSDK from "..";
import {
  GetProjectMinterConfigurationUpdatesQuery,
  ProjectMinterConfigurationDetailsFragment,
} from "../generated/graphql";
import { FormFieldSchema, BaseFormFieldSchema } from "../json-schema";
import { AsyncData, asyncPoll } from "../utils";
import {
  getAllowlistUploadUrlQueryDocument,
  getProjectMinterConfigurationUpdatesQueryDocument,
  getProjectsMetadataUpdatesQueryDocument,
  updateOffChainExtraMinterDetailsMutationDocument,
} from "./graphql-operations";
import {
  getMerkleRoot,
  readFileAsText,
  textOrCsvAddressListToArray,
} from "../utils/merkle";
import { GenerateProjectMinterConfigurationFormsContext } from ".";

export async function pollForProjectMinterConfigurationUpdates(
  sdk: ArtBlocksSDK,
  projectId: string,
  transactionConfirmedAt: Date,
  updateProperties: string[]
) {
  await asyncPoll(
    async (): Promise<
      AsyncData<
        GetProjectMinterConfigurationUpdatesQuery["projects_metadata_by_pk"]
      >
    > => {
      try {
        const result = await request(
          sdk.graphqlEndpoint,
          getProjectMinterConfigurationUpdatesQueryDocument,
          {
            projectId,
          },
          {
            Authorization: `Bearer ${sdk.jwt}`,
          }
        );
        const project = result.projects_metadata_by_pk;

        if (!project) {
          return Promise.reject(
            new Error(`Could not find project with id ${projectId}`)
          );
        }

        const transactionConfirmedAtTimestamp =
          transactionConfirmedAt.getTime();

        const hasUpdatedProperty = updateProperties.some((property) => {
          const propertyUpdatedAt = new Date(
            project.minter_configuration?.properties_updated_at?.[property] ?? 0
          );

          const propertyUpdatedAtTimestamp = propertyUpdatedAt.getTime();

          console.log({
            propertyUpdatedAtTimestamp,
            transactionConfirmedAtTimestamp,
            propertyUpdatedAt,
            transactionConfirmedAt,
            difference:
              propertyUpdatedAtTimestamp - transactionConfirmedAtTimestamp,
          });

          return propertyUpdatedAtTimestamp > transactionConfirmedAtTimestamp;
        });

        if (hasUpdatedProperty) {
          return Promise.resolve({
            done: true,
            data: project,
          });
        } else {
          return Promise.resolve({
            done: false,
          });
        }
      } catch (err) {
        return Promise.reject(err);
      }
    },
    500, // interval
    90000 // timeout
  );
}

export async function pollForProjectUpdates(
  sdk: ArtBlocksSDK,
  projectId: string,
  transactionConfirmedAt: Date,
  updateProperties: string[]
) {
  await asyncPoll(
    async (): Promise<
      AsyncData<
        GetProjectMinterConfigurationUpdatesQuery["projects_metadata_by_pk"]
      >
    > => {
      try {
        const result = await request(
          sdk.graphqlEndpoint,
          getProjectsMetadataUpdatesQueryDocument,
          {
            projectId,
          },
          {
            Authorization: `Bearer ${sdk.jwt}`,
          }
        );
        const project = result.projects_metadata_by_pk;

        if (!project) {
          return Promise.reject(
            new Error(`Could not find project with id ${projectId}`)
          );
        }

        const transactionConfirmedAtTimestamp =
          transactionConfirmedAt.getTime();

        const hasUpdatedProperty = updateProperties.some((property) => {
          const propertyUpdatedAt = new Date(
            project.properties_updated_at?.[property] ?? 0
          );

          const propertyUpdatedAtTimestamp = propertyUpdatedAt.getTime();

          return propertyUpdatedAtTimestamp > transactionConfirmedAtTimestamp;
        });

        if (hasUpdatedProperty) {
          return Promise.resolve({
            done: true,
            data: project,
          });
        } else {
          return Promise.resolve({
            done: false,
          });
        }
      } catch (err) {
        return Promise.reject(err);
      }
    },
    500, // interval
    90000 // timeout
  );
}

export function getInitialMinterConfigurationValuesForFormField(
  formField: FormFieldSchema,
  projectMinterConfiguration: ProjectMinterConfigurationDetailsFragment | null
): Record<string, any> {
  // Object to hold the initial values
  const initialValues: Record<string, any> = {};

  // Recursive function to traverse the schema and set initial values
  function recursiveInitialValues(
    schema: BaseFormFieldSchema,
    configuration: ProjectMinterConfigurationDetailsFragment | null,
    parentKey = ""
  ): void {
    // Check if the current schema is of type object and has properties
    if (schema.type === "object" && schema.properties) {
      // Iterate through the properties of the schema
      for (const [key, propSchema] of Object.entries(schema.properties)) {
        if (!propSchema || typeof propSchema !== "object") {
          continue;
        }
        // Construct the full key for the current property (e.g., "parent.child")
        const fullKey = parentKey ? `${parentKey}.${key}` : key;
        // Call the function recursively for the current property
        recursiveInitialValues(propSchema, configuration, fullKey);
      }
    } else {
      // If the current schema is a leaf field (not an object), set the initial value
      // Use the value from the configuration if present, otherwise fall back to the default value
      set(
        initialValues,
        parentKey,
        get(configuration, parentKey, schema.default ?? null)
      );
    }
  }

  // Start the recursion from the root form field
  recursiveInitialValues(formField, projectMinterConfiguration);

  // Return the populated initialValues object
  return initialValues;
}

export function mapFormValuesToArgs(
  schemaArgs: string[],
  formValues: Record<string, any>,
  projectIndex: number,
  coreContractAddress: string
): (string | number)[] {
  return schemaArgs.reduce<(string | number)[]>((acc, arg) => {
    if (arg === "projectIndex") {
      return acc.concat(projectIndex);
    }

    if (arg === "coreContractAddress") {
      return acc.concat(coreContractAddress);
    }

    return acc.concat(get(formValues, arg));
  }, []);
}

type TransformProjectMinterConfigurationFormValuesArgs =
  GenerateProjectMinterConfigurationFormsContext & {
    formValues: Record<string, any>;
    schema: FormFieldSchema;
    minterConfiguration: NonNullable<ProjectMinterConfigurationDetailsFragment>;
  };

export async function transformProjectMinterConfigurationFormValues(
  args: TransformProjectMinterConfigurationFormValuesArgs
) {
  const { formValues, schema } = args;

  // Iterate through form values and look them up in the schema
  // to see if they have submissionTransformation set. If they
  // do, apply the relevant transformation.
  let transformedFormValues: Record<string, any> = {};
  for (const [key, value] of Object.entries(formValues)) {
    const fieldSchema = schema.properties?.[key];
    if (typeof fieldSchema === "object" && fieldSchema.submissionProcessing) {
      switch (fieldSchema.submissionProcessing) {
        case "merkleRoot": {
          const merkleRoot = await processAllowlistFileToMerkleRoot(
            value,
            args
          );
          transformedFormValues[key] = merkleRoot;
          break;
        }
        case "tokenHolderAllowlist": {
          const allowRemoveArgs = processProjectContractTokenHolderList(
            value,
            args
          );

          transformedFormValues = {
            ...transformedFormValues,
            ...allowRemoveArgs,
          };
        }
      }
    } else {
      transformedFormValues[key] = value;
    }
  }

  return transformedFormValues;
}

async function processAllowlistFileToMerkleRoot(
  value: unknown,
  args: TransformProjectMinterConfigurationFormValuesArgs
): Promise<string> {
  const {
    sdk,
    projectId,
    minterConfiguration,
    allowedPrivilegedRolesForProject,
  } = args;

  // Expect the form value to be a FileList
  if (!(value instanceof FileList && value.length > 0)) {
    throw new Error(
      "Unexpected form value for merkle root transformation. Please provide a text or csv file."
    );
  }

  const file = value[0];
  const fileType = value[0].type;

  // Expect the file to be a text or csv file
  if (!(fileType === "text/plain" || fileType === "text/csv")) {
    throw new Error(
      "Unexpected file type for merkle root transformation. Please provide a text or csv file."
    );
  }

  // If we have an expected type convert the contents of the file to an Array
  const allowlistFileText = await readFileAsText(file);
  const allowlist = textOrCsvAddressListToArray(allowlistFileText);

  // Get upload signed s3 upload url for allowlist file
  const getAllowlistUploadUrlRes = await request(
    sdk.graphqlEndpoint,
    getAllowlistUploadUrlQueryDocument,
    {
      projectId,
    },
    {
      Authorization: `Bearer ${sdk.jwt}`,
    }
  );

  if (
    !getAllowlistUploadUrlRes.getAllowlistUploadUrl?.key ||
    !getAllowlistUploadUrlRes.getAllowlistUploadUrl?.url
  ) {
    throw new Error("Unexpected response from server. Please try again.");
  }

  // Get signed s3 upload url for allowlist file
  const { url } = getAllowlistUploadUrlRes.getAllowlistUploadUrl;

  // Upload allowlist file to s3 as a json file
  await fetch(url, {
    method: "PUT",
    body: JSON.stringify(allowlist),
    headers: {
      "x-amz-acl": "public-read",
      "Content-Type": "application/json",
    },
  });

  // Generate merkle root from allowlist
  const merkleRoot = getMerkleRoot(allowlist);

  // Store the proposed merkleRoot and allowlist file url in the database
  // the pendingRoot will be confirmed once the transaction is confirmed
  // and the merkle root syncs to our db. The pendingAllowlistedAddressesLink
  // is only ever available off-chain. We save it as a pending value until
  // we can confirm the synced merkle root matches the merkle root we generated
  // from the pending list.
  await request(
    sdk.graphqlEndpoint,
    updateOffChainExtraMinterDetailsMutationDocument,
    {
      projectMinterConfigId: minterConfiguration.id,
      extraMinterDetails: {
        pendingMerkleRoot: merkleRoot,
        pendingAllowlistedAddressesLink: url.split("?")[0],
      },
    },
    {
      "x-hasura-role": (() => {
        if (allowedPrivilegedRolesForProject.includes("staff")) {
          return "staff";
        } else if (allowedPrivilegedRolesForProject.includes("allowlisted")) {
          return "allowlisted";
        } else if (allowedPrivilegedRolesForProject.includes("artist")) {
          return "artist";
        } else {
          return "base_user";
        }
      })(),
    }
  );

  return merkleRoot;
}

type RemoveHoldersOfProjectArgs = {
  ownedNFTAddressesRemove: string[];
  ownedNFTProjectIdsRemove: string[];
};

type AllowHoldersOfProjectsArgs = {
  ownedNFTAddressesAdd: string[];
  ownedNFTProjectIdsAdd: string[];
};

function processProjectContractTokenHolderList(
  value: unknown,
  args: TransformProjectMinterConfigurationFormValuesArgs
): AllowHoldersOfProjectsArgs & RemoveHoldersOfProjectArgs {
  const { minterConfiguration } = args;

  // Expect the form value to be an array of strings
  if (!Array.isArray(value) || !value.every((val) => typeof val === "string")) {
    throw new Error("Unexpected form value for token holder allowlist.");
  }

  const currentlyAllowedProjectIds: string[] =
    minterConfiguration.extra_minter_details.allowlistedAddressAndProjectId ??
    [];
  const updatedAllowedProjectIds = value;

  // Expect the list to be submitted as a single array of strings of the formate
  // <contract address>-<project index>. This is the format of project ids in our db.
  const addedProjectIds: string[] = difference(
    updatedAllowedProjectIds,
    currentlyAllowedProjectIds
  );

  const removedProjectIds: string[] = difference(
    currentlyAllowedProjectIds,
    updatedAllowedProjectIds
  );

  const addArgs = addedProjectIds.reduce<AllowHoldersOfProjectsArgs>(
    (acc, id) => {
      const [contractAddress, projectIndex] = id.split("-");
      return {
        ownedNFTAddressesAdd: [...acc.ownedNFTAddressesAdd, contractAddress],
        ownedNFTProjectIdsAdd: [...acc.ownedNFTProjectIdsAdd, projectIndex],
      };
    },
    {} as AllowHoldersOfProjectsArgs
  );

  // Split both add and remove lists into split arrays one for the
  // contract address and one for project index (id on the contract)
  const removeArgs = removedProjectIds.reduce<RemoveHoldersOfProjectArgs>(
    (acc, id) => {
      const [contractAddress, projectIndex] = id.split("-");
      return {
        ownedNFTAddressesRemove: [
          ...acc.ownedNFTAddressesRemove,
          contractAddress,
        ],
        ownedNFTProjectIdsRemove: [
          ...acc.ownedNFTProjectIdsRemove,
          projectIndex,
        ],
      };
    },
    {} as RemoveHoldersOfProjectArgs
  );

  return {
    ...removeArgs,
    ...addArgs,
  };
}

export function getAllowedPrivilegedRoles(
  userIsStaff: boolean,
  userIsAllowlisted: boolean,
  userIsArtist: boolean
) {
  const roles = [];
  if (userIsStaff) {
    roles.push("staff");
  }
  if (userIsAllowlisted) {
    roles.push("allowlisted");
  }
  if (userIsArtist) {
    roles.push("artist");
  }
  return roles;
}
