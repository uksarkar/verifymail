import { SPF_MECHANISM, SPF_MODIFIERS, SPF_QUALIFIERS } from '../utils/constants';

type SPFRecord =
  | {
      type: 'mechanism';
      host: string;
      token: typeof SPF_MECHANISM[number];
    }
  | {
      type: 'modifier';
      token: typeof SPF_MODIFIERS[number];
      qualifier?: typeof SPF_QUALIFIERS[number];
    };

export default SPFRecord;
