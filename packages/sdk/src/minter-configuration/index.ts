import request from "graphql-request";
import ArtBlocksSDK from "../index";
import {
  ConfigurationForm,
  SubmissionStatus,
  SubmissionStatusEnum,
  filterProjectIdFromFormSchema,
  minterSelectionSchema,
} from "../minters";
import { getProjectMinterConfigurationQueryDocument } from "./graphql-operations";
import { useFragment } from "../generated";
import {
  GetProjectMinterConfigurationQuery,
  ProjectMinterConfigurationDetailsFragment,
  ProjectMinterConfigurationDetailsFragmentDoc,
} from "../generated/graphql";
import {
  ConfigurationSchema,
  FormFieldSchema,
  isOnChainFormFieldSchema,
} from "../json-schema";
import { formFieldSchemaToZod } from "../utils";
import { submitTransaction } from "../utils/web3";
import { Abi, Hex, WalletClient } from "viem";
import {
  getAllowedPrivilegedRoles,
  getInitialMinterConfigurationValuesForFormField,
  mapFormValuesToArgs,
  pollForProjectMinterConfigurationUpdates,
  pollForProjectUpdates,
  transformProjectMinterConfigurationFormValues,
} from "./utils";
import get from "lodash/get";

type GenerateProjectMinterConfigurationFormsArgs = {
  projectId: string;
  onConfigurationChange: (configuration: ConfigurationForm[]) => void;
  sdk: ArtBlocksSDK;
};

export type GenerateProjectMinterConfigurationFormsContext =
  GenerateProjectMinterConfigurationFormsArgs & {
    allowedPrivilegedRolesForProject: string[];
    coreContractAddress: string;
    projectIndex: number;
    project: ProjectWithMinterFilter;
  };

type ProjectWithMinterFilter = NonNullable<
  GetProjectMinterConfigurationQuery["projects_metadata_by_pk"]
> & {
  contract: {
    minter_filter: {
      address: string;
    };
  };
};

export async function generateProjectMinterConfigurationForms(
  args: GenerateProjectMinterConfigurationFormsArgs
): Promise<ConfigurationForm[]> {
  const { projectId, sdk } = args;
  const [coreContractAddress, projectIndexString] = projectId.split("-");
  const projectIndex = Number(projectIndexString);

  // Get current minter configuration details from the database
  const res = await request(
    sdk.graphqlEndpoint,
    getProjectMinterConfigurationQueryDocument,
    {
      projectId,
    },
    {
      Authorization: `Bearer ${sdk.jwt}`,
    }
  );
  const project = res.projects_metadata_by_pk;

  if (!project) {
    throw new Error(`Could not find project with id ${projectId}`);
  }

  if (!project.contract.minter_filter) {
    throw new Error(
      `Project with id ${projectId} is not on a contract with an associated minter filter`
    );
  }

  const allowedPrivilegedRolesForProject = getAllowedPrivilegedRoles(
    sdk.userIsStaff,
    project.contract.user_is_allowlisted ?? false,
    project.user_is_artist ?? false
  );

  const context: GenerateProjectMinterConfigurationFormsContext = {
    ...args,
    allowedPrivilegedRolesForProject,
    coreContractAddress,
    projectIndex,
    project: project as ProjectWithMinterFilter,
  };

  const minterSelectionForm = generateSelectMinterForm(context);
  let configurationForms = [minterSelectionForm];

  // If no minter has been selected, return only the minter selection form
  const minterConfiguration = useFragment(
    ProjectMinterConfigurationDetailsFragmentDoc,
    res.projects_metadata_by_pk?.minter_configuration
  );

  if (!minterConfiguration || !minterConfiguration.minter) {
    return configurationForms;
  }

  const minterConfigurationSchema: ConfigurationSchema =
    minterConfiguration.minter.type?.project_configuration_schema;

  if (!minterConfigurationSchema) {
    console.warn("No minter configuration schema found for project", projectId);
    return configurationForms;
  }

  configurationForms = configurationForms.concat(
    Object.entries(minterConfigurationSchema.properties).map(([key, value]) => {
      return generateMinterForm({
        ...context,
        key,
        formSchema: value,
        minterConfiguration,
      });
    })
  );

  return configurationForms;
}

// Form to choose a minter
function generateSelectMinterForm({
  sdk,
  project,
  projectId,
  projectIndex,
  coreContractAddress,
  onConfigurationChange,
}: GenerateProjectMinterConfigurationFormsContext): ConfigurationForm {
  const minterConfiguration = useFragment(
    ProjectMinterConfigurationDetailsFragmentDoc,
    project.minter_configuration
  );

  // Map available minters to oneOf entries on the minter.address
  // property of the minter selection form schema
  const minterSelectionSchemaWithMinters = minterSelectionSchema;
  if (minterSelectionSchemaWithMinters.properties?.["minter.address"]) {
    const globallyAllowedMinters =
      project.contract.minter_filter.globally_allowed_minters ?? [];
    const latestMinters = globallyAllowedMinters.reduce(
      (dedupedMinters, minter) => {
        return dedupedMinters.filter((mntr) => {
          return (
            minterConfiguration?.minter?.address === mntr.address ||
            mntr.type?.unversioned_type !== minter.type?.unversioned_type ||
            (mntr.type?.version_number || 0) >=
              (minter.type?.version_number || 0)
          );
        });
      },
      globallyAllowedMinters
    );

    minterSelectionSchemaWithMinters.properties["minter.address"].oneOf =
      latestMinters.map((minter) => ({
        const: minter.address,
        title: `${minter.type?.label ?? ""} - ${minter.address}`,
      }));
  }

  // Initialize configurationForms with the minter selection form
  const form = {
    key: "setMinterForProject",
    formSchema: minterSelectionSchemaWithMinters,
    initialFormValues: getInitialMinterConfigurationValuesForFormField(
      minterSelectionSchema,
      minterConfiguration ?? null
    ),
    zodSchema: formFieldSchemaToZod(minterSelectionSchema),
    handleSubmit: async (
      formValues: Record<string, any>,
      walletClient: WalletClient,
      onProgress?: (status: SubmissionStatus) => void
    ) => {
      // We need basic information about the project and the
      // minter to submit the transaction
      if (
        !project ||
        !project.contract.minter_filter ||
        !get(formValues, "minter.address") ||
        !walletClient.account
      ) {
        console.warn("handleSubmit called without required data");
        return;
      }

      onProgress?.(SubmissionStatusEnum.AWAITING_USER_SIGNATURE);

      // Get the minter filter address for minter selection
      const minterFilterAddress: Hex = project.contract.minter_filter
        .address as Hex;

      // Map the form values to an array of arguments expected by the smart contract function
      const functionArgs = mapFormValuesToArgs(
        minterSelectionSchema.transactionDetails.args,
        formValues,
        projectIndex,
        coreContractAddress
      );

      // Submit the transaction
      await submitTransaction({
        publicClient: sdk.publicClient,
        walletClient,
        address: minterFilterAddress,
        abi: minterSelectionSchema.transactionDetails.abi as Abi,
        functionName: minterSelectionSchema.transactionDetails.functionName,
        args: functionArgs,
        onUserAccepted: () => {
          onProgress?.(SubmissionStatusEnum.CONFIRMING);
        },
      });

      onProgress?.(SubmissionStatusEnum.SYNCING);

      // Save the time the transaction was confirmed
      const transactionConfirmedAt = new Date();

      // Poll for updates to the configuration, this will return
      // when the minter_address column has been updated to a
      // time after the transaction was confirmed
      await pollForProjectUpdates(sdk, projectId, transactionConfirmedAt, [
        "minter_configuration_id",
      ]);

      const updatedForms = await generateProjectMinterConfigurationForms({
        sdk,
        onConfigurationChange,
        projectId,
      });

      // Alert subscribers that the configuration change has been confirmed
      // and synced to the database
      onConfigurationChange(updatedForms);
    },
  };

  return form;
}

type GenerateMinterFormArgs = GenerateProjectMinterConfigurationFormsContext & {
  key: string;
  formSchema: FormFieldSchema;
  minterConfiguration: NonNullable<ProjectMinterConfigurationDetailsFragment>;
};

// Forms to configure a minter for a project
function generateMinterForm(args: GenerateMinterFormArgs): ConfigurationForm {
  const {
    sdk,
    key,
    projectId,
    formSchema,
    projectIndex,
    coreContractAddress,
    minterConfiguration,
    onConfigurationChange,
  } = args;

  const schemaWithProjectIdFiltered = filterProjectIdFromFormSchema(formSchema);

  const initialFormValues = getInitialMinterConfigurationValuesForFormField(
    schemaWithProjectIdFiltered,
    minterConfiguration
  );

  return {
    key,
    formSchema: schemaWithProjectIdFiltered,
    initialFormValues,
    zodSchema: formFieldSchemaToZod(schemaWithProjectIdFiltered),
    handleSubmit: async (
      formValues: Record<string, any>,
      walletClient: WalletClient,
      onProgress?: (status: SubmissionStatus) => void
    ) => {
      if (
        !minterConfiguration.minter ||
        !isOnChainFormFieldSchema(schemaWithProjectIdFiltered) ||
        !schemaWithProjectIdFiltered.transactionDetails ||
        !walletClient.account
      ) {
        throw new Error("Invalid form configuration");
      }

      onProgress?.(SubmissionStatusEnum.AWAITING_USER_SIGNATURE);

      // Check if any of the form values should be transformed before submitting the transaction
      // const transformedForm;
      const transformedFormValues =
        await transformProjectMinterConfigurationFormValues({
          ...args,
          formValues,
          schema: formSchema,
        });

      const functionArgs = mapFormValuesToArgs(
        schemaWithProjectIdFiltered.transactionDetails.args,
        transformedFormValues,
        projectIndex,
        coreContractAddress
      );

      await submitTransaction({
        publicClient: sdk.publicClient,
        walletClient,
        address: minterConfiguration.minter.address as `0x${string}`,
        abi: schemaWithProjectIdFiltered.transactionDetails.abi as Abi,
        functionName:
          schemaWithProjectIdFiltered.transactionDetails.functionName,
        args: functionArgs, // sdk needs to come from values,
        onUserAccepted: () => onProgress?.(SubmissionStatusEnum.CONFIRMING),
      });

      onProgress?.(SubmissionStatusEnum.SYNCING);
      const transactionConfirmedAt = new Date();

      const expectedUpdates =
        schemaWithProjectIdFiltered.transactionDetails.args;

      // Poll for updates to the configuration
      await pollForProjectMinterConfigurationUpdates(
        sdk,
        projectId,
        transactionConfirmedAt,
        expectedUpdates
      );

      onConfigurationChange(
        await generateProjectMinterConfigurationForms(args)
      );
    },
  };
}
