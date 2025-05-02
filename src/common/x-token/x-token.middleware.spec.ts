import { XTokenMiddleware } from './x-token.middleware';

describe('XTokenMiddleware', () => {
  it('should be defined', () => {
    expect(new XTokenMiddleware()).toBeDefined();
  });
});
