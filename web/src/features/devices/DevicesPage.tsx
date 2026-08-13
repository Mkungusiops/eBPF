import { useMemo } from "react";

import { api as sharedApi, type ApiMethod, type ApiOptions } from "../../lib/api";
import { createDevicesApi, type ApiRequest } from "./api";
import { DevicesRoute } from "./DevicesRoute";

export function DevicesPage() {
  const devicesApi = useMemo(() => createDevicesApi(sharedRequest), []);
  return <DevicesRoute api={devicesApi} />;
}

const sharedRequest: ApiRequest = (url, init = {}) => {
  return sharedApi(url, toApiOptions(init));
};

function toApiOptions(init: RequestInit): ApiOptions {
  const options: ApiOptions = {
    ...init,
    method: init.method as ApiMethod | undefined
  };

  if (init.body != null) {
    options.body = decodeRequestBody(init.body);
  }

  return options;
}

function decodeRequestBody(body: BodyInit): unknown {
  if (typeof body !== "string") return body;
  try {
    return JSON.parse(body) as unknown;
  } catch {
    return body;
  }
}
