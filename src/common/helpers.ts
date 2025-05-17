//src/helpers/helpers.ts
import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { createClient, RedisClientType } from '@redis/client';


export class CommonHelpers {
    static readonly MAX_RETRIES = 3;
    static readonly DEFAULT_TTL = 300; // 5 minutes
    public static redisClient: RedisClientType;

    static initializeRedisClient(): RedisClientType {
        if (!this.redisClient) {
            this.redisClient = createClient({
                url: `redis://${process.env.REDIS_HOST || 'localhost'}:${process.env.REDIS_PORT || 6379}`,
            });
            this.redisClient.connect()
                .then(() => {
                    console.log('Connected to Redis successfully');
                })
                .catch((err) => {
                    console.error('Failed to connect to Redis:', err.message);
                });

            process.on('SIGINT', async () => {
                await this.redisClient.quit();
                console.log('Redis client disconnected');
                process.exit(0);
            });
        }
        return this.redisClient;
    }

    static async retry<T>(operation: () => Promise<T>): Promise<T> {
        let attempt = 0;
        while (attempt < this.MAX_RETRIES) {
            try {
                console.log(`Attempt ${attempt + 1}`);
                return await operation();
            } catch (error) {
                attempt++;
                console.error(`Attempt ${attempt} failed: ${error.message}`);
                // Only skip throwing for ECONNRESET, throw for all other errors
                if (
                    !(error.code && error.code === 'ECONNRESET')
                ) {
                    throw error;
                }
                if (attempt === this.MAX_RETRIES) {
                    throw new HttpException(
                        `Operation failed after ${this.MAX_RETRIES} attempts: ${error.message}`,
                        HttpStatus.INTERNAL_SERVER_ERROR,
                    );
                }
                await new Promise((resolve) => setTimeout(resolve, 1000 * attempt));
            }
        }
        throw new HttpException('Unexpected error in retry logic', HttpStatus.INTERNAL_SERVER_ERROR);
    }

    static async cacheOrFetch<T>(
        cacheKey: string,
        fetchFn: () => Promise<T>,
        ttl: number = this.DEFAULT_TTL,
        setName?: string
    ): Promise<T> {
        if (!this.redisClient?.isOpen) {
            console.warn(`Redis not connected; skipping cache for ${cacheKey}`);
            return this.retry(fetchFn);
        }
        try {
            const cachedData = await this.redisClient.get(cacheKey);
            console.log(`Cache lookup for ${cacheKey}:`, cachedData ? 'Hit' : 'Miss');
            if (cachedData) {
                try {
                    return JSON.parse(cachedData) as T;
                } catch (parseError) {
                    console.error(`Invalid cache data for ${cacheKey}: ${parseError.message}`);
                    // Fall back to fetchFn on parse error
                }
            }

            const data = await this.retry(fetchFn);
            try {
                await this.redisClient.set(cacheKey, JSON.stringify(data), { EX: ttl });
                console.log(`Setting cache for ${cacheKey} with TTL: ${ttl}s`);

                if (setName) {
                    await this.redisClient.sAdd(setName, cacheKey);
                    console.log(`Added ${cacheKey} to set: ${setName}`);
                }
            } catch (cacheSetError) {
                console.error(`Failed to set cache for ${cacheKey}: ${cacheSetError.message}`);
            }
            return data;
        } catch (error) {
            console.error(`Cache error for ${cacheKey}: ${error.message}`);
            return this.retry(fetchFn);
        }
    }

    static async invalidateCache(cacheKeys: string[]): Promise<void> {
        if (!this.redisClient?.isOpen) {
            console.warn('Redis not connected; skipping cache invalidation');
            return;
        }

        if (cacheKeys.length === 0) {
            return;
        }
        try {
            await this.redisClient.del(cacheKeys);
            console.log(`Invalidated ${cacheKeys.length} keys: ${cacheKeys.join(', ')}`);
        } catch (error) {
            console.error(`Failed to invalidate cache for keys: ${cacheKeys.join(', ')} - ${error.message}`);
        }
    }

    static async invalidateCacheByPattern(pattern: string): Promise<void> {
        try {
            let cursor = '0';
            let totalKeysDeleted = 0;

            do {
                const scanResult = await this.redisClient.scan(Number(cursor), { MATCH: pattern, COUNT: 100 });
                const nextCursor = scanResult.cursor;
                const keys = scanResult.keys;
                cursor = String(nextCursor);

                if (keys.length > 0) {
                    await this.redisClient.del(keys);
                    totalKeysDeleted += keys.length;
                    console.log(`Deleted ${keys.length} keys matching pattern: ${pattern}`);
                }
            } while (cursor !== '0');

            console.log(`Invalidated ${totalKeysDeleted} keys for pattern: ${pattern}`);
        } catch (error) {
            console.error(`Failed to invalidate cache for pattern: ${pattern} - ${error.message}`);
            // Optionally, throw an error or handle it based on your needs
            // throw new HttpException(`Failed to invalidate cache: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    static transformDocument(document: any): any {
        return { ...document, _id: document._id.toString() };
    }

}

@Injectable()
export class ResponseService {

    responseSuccess(data: any): any {
        const response = {
            statusCode: 200,
            message: 'success',
            data: data ? data : null,
            meta: {
                timestamp: new Date().toISOString(),
            },

        };
        return response;
    }

    responseError(error: string): any {
        const response = {
          statusCode: 400,
          message: error,
          meta: {
                timestamp: new Date().toISOString(),
            },
        };
        return response;
    }

    responseInternalError(error: string): any {
        const response = {
            message: error,
        };
        return response;
    }
}