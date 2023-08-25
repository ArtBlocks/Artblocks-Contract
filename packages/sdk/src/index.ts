import {
  ConfigurationForm,
  SubmissionStatusEnum,
  SubmissionStatus,
} from "./minters";
import { PublicClient } from "viem";
import { generateProjectMinterConfigurationForms } from "./minter-configuration";
import { GetProjectMinterConfigurationQuery } from "./generated/graphql";

export type ArtBlocksSDKOptions = {
  publicClient: PublicClient;
  graphqlEndpoint: string;
  jwt?: string;
};

export default class ArtBlocksSDK {
  publicClient: PublicClient;
  graphqlEndpoint: string;
  jwt?: string;
  userIsStaff: boolean;

  constructor({ publicClient, jwt, graphqlEndpoint }: ArtBlocksSDKOptions) {
    this.publicClient = publicClient;
    this.jwt = jwt;
    this.graphqlEndpoint = graphqlEndpoint;

    const jwtString = Buffer.from(
      this.jwt?.split(".")[1] ?? "",
      "base64"
    ).toString();
    const jwtData = jwtString ? JSON.parse(jwtString) : null;

    this.userIsStaff = jwtData?.isStaff ?? false;
  }

  async getProjectMinterConfiguration(projectId: string) {
    // Create a list of subscribers
    let subscribers: Array<
      (config: { data: ProjectConfigData; forms: ConfigurationForm[] }) => void
    > = [];

    const notifySubscribers = (updatedConfig: {
      data: ProjectConfigData;
      forms: ConfigurationForm[];
    }) => {
      for (const subscriber of subscribers) {
        subscriber(updatedConfig);
      }
    };

    // Load the initial configuration
    const { forms, data } = await generateProjectMinterConfigurationForms({
      projectId,
      onConfigurationChange: notifySubscribers,
      sdk: this,
    });

    return {
      data,
      // Provide a method to access the current configuration
      forms,

      // Provide a method to refresh the configuration
      refresh: async () => {
        await generateProjectMinterConfigurationForms({
          projectId,
          onConfigurationChange: notifySubscribers,
          sdk: this,
        });
      },

      // Provide a method to subscribe to changes in the configuration
      subscribe: (
        callback: (config: {
          data: ProjectConfigData;
          forms: ConfigurationForm[];
        }) => void
      ) => {
        subscribers.push(callback);

        // Provide a way to unsubscribe
        return () => {
          subscribers = subscribers.filter(
            (subscriber) => subscriber !== callback
          );
        };
      },
    };
  }
}

export type ProjectConfigData =
  GetProjectMinterConfigurationQuery["projects_metadata_by_pk"];

export { type ConfigurationForm, SubmissionStatusEnum, type SubmissionStatus };
