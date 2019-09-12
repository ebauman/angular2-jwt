import { Injectable, Inject } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor
} from '@angular/common/http';
import { JwtHelperService } from './jwthelper.service';
import { JWT_OPTIONS } from './jwtoptions.token';
import { Observable, from } from "rxjs";
import { mergeMap } from 'rxjs/operators';
import { parse } from 'url';

@Injectable()
export class JwtInterceptor implements HttpInterceptor {
  tokenGetter: () => string | null | Promise<string | null>;
  headerName: string;
  authScheme: string;
  whitelistedDomains: () => Array<string | RegExp> | Promise<Array<string | RegExp>>;
  blacklistedRoutes: () => Array<string | RegExp> | Promise<Array<string | RegExp>>;
  throwNoTokenError: boolean;
  skipWhenExpired: boolean;

  constructor(
    @Inject(JWT_OPTIONS) config: any,
    public jwtHelper: JwtHelperService
  ) {
    this.tokenGetter = config.tokenGetter;
    this.headerName = config.headerName || 'Authorization';
    this.authScheme =
      config.authScheme || config.authScheme === ''
        ? config.authScheme
        : 'Bearer ';
    this.whitelistedDomains = config.whitelistedDomains || [];
    this.blacklistedRoutes = config.blacklistedRoutes || [];
    this.throwNoTokenError = config.throwNoTokenError || false;
    this.skipWhenExpired = config.skipWhenExpired;
  }

  isWhitelistedDomain(request: HttpRequest<any>): boolean {
    const wListDomains = this.whitelistedDomains();

    var valid: boolean = false;

    if (wListDomains instanceof Promise) {
      wListDomains.then(
        (a: Array<string | RegExp>) => {
          valid = this._validWhitelistedDomain(a, request);
        }
      )
    } else {
      valid = this._validWhitelistedDomain(wListDomains, request);
    }

    return valid;
  }

  _validWhitelistedDomain(domains: Array<string | RegExp>, request: HttpRequest<any>) {
    const requestUrl: any = parse(request.url, false, true);
    return (
      requestUrl.host === null ||
      domains.findIndex(
        domain =>
          typeof domain === 'string'
            ? domain === requestUrl.host
            : domain instanceof RegExp
              ? domain.test(requestUrl.host)
              : false
      ) > -1
    );
  }

  isBlacklistedRoute(request: HttpRequest<any>): boolean {
    const bListRoutes = this.blacklistedRoutes();

    var valid: boolean = false;

    if (bListRoutes instanceof Promise) {
      bListRoutes.then(
        (a: Array<string | RegExp>) => {
          valid = this._validBlacklistedRoute(a, request);
        }
      )
    } else {
      valid = this._validBlacklistedRoute(bListRoutes, request);
    }

    return valid;
  }

  _validBlacklistedRoute(routes: Array<string | RegExp>, request: HttpRequest<any>): boolean {
    const url = request.url;

    return (
      routes.findIndex(
        route =>
          typeof route === 'string'
            ? route === url
            : route instanceof RegExp
              ? route.test(url)
              : false
      ) > -1
    );
  }

  handleInterception(
    token: string | null,
    request: HttpRequest<any>,
    next: HttpHandler
  ) {
    let tokenIsExpired: boolean = false;

    if (!token && this.throwNoTokenError) {
      throw new Error('Could not get token from tokenGetter function.');
    }

    if (this.skipWhenExpired) {
      tokenIsExpired = token ? this.jwtHelper.isTokenExpired(token) : true;
    }

    if (token && tokenIsExpired && this.skipWhenExpired) {
      request = request.clone();
    } else if (token) {
      request = request.clone({
        setHeaders: {
          [this.headerName]: `${this.authScheme}${token}`
        }
      });
    }
    return next.handle(request);
  }

  intercept(
    request: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {
    if (
      !this.isWhitelistedDomain(request) ||
      this.isBlacklistedRoute(request)
    ) {
      return next.handle(request);
    }
    const token = this.tokenGetter();

    if (token instanceof Promise) {
      return from(token).pipe(mergeMap(
        (asyncToken: string | null) => {
          return this.handleInterception(asyncToken, request, next);
        }
      ));
    } else {
      return this.handleInterception(token, request, next);
    }
  }
}
